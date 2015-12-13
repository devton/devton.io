
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE SCHEMA IF NOT EXISTS auth;
COMMENT ON SCHEMA auth IS 'Schema to handle with user authentication context';

CREATE SEQUENCE auth.users_id_seq
       START WITH 1
       INCREMENT BY 1
       NO MINVALUE
       NO MAXVALUE
       CACHE 1;
COMMENT ON SEQUENCE auth.users_id_seq IS 'Used to generate user primary keys';

CREATE TABLE IF NOT EXISTS auth.users (
       id integer PRIMARY KEY DEFAULT nextval('auth.users_id_seq'::regclass),
       login text CHECK (length(login) < 30),
       email text NOT NULL CHECK (email ~* '^.+@.+\..+$'),
       password text NOT NULL CHECK (length(password) < 512),
       role name NOT NULL CHECK(length(role) < 512),
       verified boolean NOT NULL DEFAULT false
);
COMMENT ON TABLE auth.users IS 'Table with user login data';

ALTER SEQUENCE auth.users_id_seq OWNED BY auth.users.id;

CREATE OR REPLACE FUNCTION auth.check_role_exists() RETURNS TRIGGER
       LANGUAGE plpgsql
       AS $$
          BEGIN
            IF NOT EXISTS (SELECT * FROM pg_roles AS r WHERE r.rolname = NEW.role) THEN
               RAISE foreign_key_violation USING message = 'unknown database role: ' || NEW.role;

               RETURN NULL;
            END IF;

            RETURN NEW;
          END;
        $$;
COMMENT ON FUNCTION auth.check_role_exists() IS 'Used to check if role that user is using exists on pg_role';


DROP TRIGGER IF EXISTS ensure_user_role_exists ON auth.users;
CREATE CONSTRAINT TRIGGER ensure_user_role_exists
       AFTER INSERT OR UPDATE ON auth.users
       FOR EACH ROW
       EXECUTE PROCEDURE auth.check_role_exists();
COMMENT ON TRIGGER ensure_user_role_exists ON auth.users IS 'Used for ensure that role name exists when user is updated or inserted';

CREATE OR REPLACE FUNCTION auth.encrypt_pass() RETURNS TRIGGER
       LANGUAGE plpgsql
       AS $$
          BEGIN
            IF TG_OP = 'INSERT' OR NEW.pass <> OLD.pass THEN
               NEW.pass = crypt(NEW.pass, gen_salt('bf'));
            END IF;

            RETURN NEW;
          END;
       $$;
COMMENT ON FUNCTION auth.encrypt_pass() IS 'handles with user password encryption';

DROP TRIGGER IF EXISTS encrypt_pass ON auth.users;
CREATE TRIGGER encrypt_pass
       BEFORE INSERT OR UPDATE ON auth.users
       FOR EACH ROW
       EXECUTE PROCEDURE auth.encrypt_pass();
COMMENT ON TRIGGER encrypt_pass ON auth.users IS 'Used for encrypt password when insert new user or udpate';
-- +goose StatementEnd


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP SCHEMA IF EXISTS auth CASCADE;

