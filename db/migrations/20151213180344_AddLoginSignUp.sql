
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- +goose StatementBegin

CREATE ROLE IF NOT EXISTS admin NOLOGIN;
CREATE ROLE IF NOT EXISTS member NOLOGIN;
CREATE ROLE IF NOT EXISTS anonymous NOLOGIN;

INSERT INTO auth.users (login, email, password, role) VALUES
       ('demo', 'demo@demo.com', 'demo123', 'admin'); -- creates an admin

CREATE OR REPLACE FUNCTION signup(login text, email text, pass text) RETURNS void
       LANGUAGE sql
       AS $$
          INSERT INTO auth.users (login, email, password, role) VALUES
                 (signup.login, signup.email, signup.password, 'member');
       $$;
COMMENT ON FUNCTION signup IS 'Creates an member user at database';

DROP TYPE IF EXISTS auth.jwt_claims CASCADE;
CREATE TYPE auth.jwt_claims AS (role text, login text, uid integer);
COMMENT ON TYPE auth.jwt_claims IS 'Auth JWT structure';

CREATE OR REPLACE FUNCTION auth.user_role(email text, pass text) RETURNS name
       LANGUAGE sql STABLE
       AS $$
          SELECT role FROM auth.users u
                 WHERE u.email = user_role.email
                 AND u.password = crypt(user_role.pass, u.password);
       $$;

CREATE OR REPLACE FUNCTION login(email text, pass text) RETURNS auth.jwt_claims
       LANGUAGE plpgsql
       AS $$
          DECLARE
            _role name;
            result auth.jwt_claims;
          BEGIN
            SELECT auth.user_role(email, pass) into _role;

            IF _role IS NULL THEN
               RAISE invalid_password USING message = 'invalid user or password';
            END IF;

            SELECT
              _role as role,
              u.login as login,
              u.id as uid
            FROM auth.users u
            WHERE u.email = login.email
            INTO result;

            RETURN result;
          END;
       $$;
COMMENT ON FUNCTION login IS 'Login functions handles that return jwt token';

CREATE OR REPLACE FUNCTION auth.current_user_uid() RETURNS integer
       LANGUAGE plpgsql
       as $$
          BEGIN
            RETURN current_setting('postgrest.claims.uid')::integer;
          EXCEPTION
            WHEN undefined_object THEN return NULL;
          END;
       $$;
COMMENT ON FUNCTION auth.current_user_uid() IS 'Returns the auth.users.id from the user logged';


-- +goose StatementEnd


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

-- +goose StatementBegin

DROP ROLE IF EXISTS admin;
DROP ROLE IF EXISTS anonymous;

DELETE auth.users WHERE login = 'demo';

DROP FUNCTION signup(login text, email text, pass text);

DROP TYPE IF EXISTS auth.jwt_claims CASCADE;

-- +goose StatementEnd

