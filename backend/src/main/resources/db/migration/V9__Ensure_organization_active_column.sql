SET @active_column_exists = (
    SELECT COUNT(*)
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'organizations'
      AND column_name = 'active'
);

SET @active_column_ddl = IF(
    @active_column_exists = 0,
    'ALTER TABLE organizations ADD COLUMN active BIT(1) NOT NULL DEFAULT b''0''',
    'ALTER TABLE organizations ALTER COLUMN active SET DEFAULT b''0'''
);

PREPARE active_column_statement FROM @active_column_ddl;
EXECUTE active_column_statement;
DEALLOCATE PREPARE active_column_statement;
