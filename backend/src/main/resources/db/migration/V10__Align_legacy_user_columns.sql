ALTER TABLE users
    MODIFY COLUMN status VARCHAR(32) NOT NULL;

SET @full_name_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'full_name'
);

SET @full_name_column_ddl = IF(
    @full_name_column_exists = 0,
    'SET @migration_noop = 1',
    'ALTER TABLE users MODIFY COLUMN full_name VARCHAR(150) NULL'
);

PREPARE full_name_column_statement FROM @full_name_column_ddl;
EXECUTE full_name_column_statement;
DEALLOCATE PREPARE full_name_column_statement;

SET @password_hash_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'password_hash'
);

SET @password_hash_column_ddl = IF(
    @password_hash_column_exists = 0,
    'SET @migration_noop = 1',
    'ALTER TABLE users MODIFY COLUMN password_hash VARCHAR(255) NULL'
);

PREPARE password_hash_column_statement FROM @password_hash_column_ddl;
EXECUTE password_hash_column_statement;
DEALLOCATE PREPARE password_hash_column_statement;

SET @role_id_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users'
      AND column_name = 'role_id'
);

SET @role_id_column_ddl = IF(
    @role_id_column_exists = 0,
    'SET @migration_noop = 1',
    'ALTER TABLE users MODIFY COLUMN role_id BIGINT NULL'
);

PREPARE role_id_column_statement FROM @role_id_column_ddl;
EXECUTE role_id_column_statement;
DEALLOCATE PREPARE role_id_column_statement;
