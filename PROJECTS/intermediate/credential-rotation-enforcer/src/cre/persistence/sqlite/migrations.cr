# ===================
# ©AngelaMos | 2026
# migrations.cr
# ===================

require "db"

module CRE::Persistence::Sqlite
  module Migrations
    SCHEMA = [
      <<-SQL,
        CREATE TABLE IF NOT EXISTS credentials (
          id                  TEXT PRIMARY KEY,
          external_id         TEXT NOT NULL,
          kind                TEXT NOT NULL,
          name                TEXT NOT NULL,
          tags                TEXT NOT NULL DEFAULT '{}',
          current_version_id  TEXT,
          pending_version_id  TEXT,
          previous_version_id TEXT,
          created_at          TEXT NOT NULL,
          updated_at          TEXT NOT NULL,
          UNIQUE (kind, external_id)
        )
        SQL
      <<-SQL,
        CREATE TABLE IF NOT EXISTS credential_versions (
          id            TEXT PRIMARY KEY,
          credential_id TEXT NOT NULL REFERENCES credentials(id),
          ciphertext    BLOB NOT NULL,
          dek_wrapped   BLOB NOT NULL,
          kek_version   INTEGER NOT NULL,
          algorithm_id  INTEGER NOT NULL,
          metadata      TEXT NOT NULL DEFAULT '{}',
          generated_at  TEXT NOT NULL,
          revoked_at    TEXT
        )
        SQL
      <<-SQL,
        CREATE TABLE IF NOT EXISTS rotations (
          id              TEXT PRIMARY KEY,
          credential_id   TEXT NOT NULL,
          rotator_kind    TEXT NOT NULL,
          state           TEXT NOT NULL,
          started_at      TEXT NOT NULL,
          completed_at    TEXT,
          step_outcomes   TEXT NOT NULL DEFAULT '{}',
          failure_reason  TEXT
        )
        SQL
      <<-SQL,
        CREATE TABLE IF NOT EXISTS audit_events (
          seq               INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id          TEXT UNIQUE NOT NULL,
          occurred_at       TEXT NOT NULL,
          event_type        TEXT NOT NULL,
          actor             TEXT NOT NULL,
          target_id         TEXT,
          payload           TEXT NOT NULL,
          prev_hash         BLOB NOT NULL,
          content_hash      BLOB NOT NULL,
          hmac              BLOB NOT NULL,
          hmac_key_version  INTEGER NOT NULL
        )
        SQL
      <<-SQL,
        CREATE TABLE IF NOT EXISTS audit_batches (
          id                  TEXT PRIMARY KEY,
          start_seq           INTEGER NOT NULL,
          end_seq             INTEGER NOT NULL,
          merkle_root         BLOB NOT NULL,
          signature           BLOB NOT NULL,
          signing_key_version INTEGER NOT NULL,
          sealed_at           TEXT NOT NULL
        )
        SQL
      <<-SQL,
        CREATE TABLE IF NOT EXISTS kek_versions (
          version     INTEGER PRIMARY KEY,
          source      TEXT NOT NULL,
          source_ref  TEXT,
          created_at  TEXT NOT NULL,
          retired_at  TEXT
        )
        SQL
    ]

    def self.run(db : DB::Database) : Nil
      SCHEMA.each { |stmt| db.exec(stmt) }
    end
  end
end
