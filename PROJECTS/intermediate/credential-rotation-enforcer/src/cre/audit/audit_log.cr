# ===================
# ©AngelaMos | 2026
# audit_log.cr
# ===================

require "json"
require "uuid"
require "./hash_chain"
require "./hmac_ratchet"
require "../persistence/persistence"
require "../persistence/repos"

module CRE::Audit
  class AuditLog
    @ratchet : HmacRatchet
    @mutex : Mutex

    def initialize(@persistence : Persistence::Persistence, initial_hmac_key : Bytes, @hmac_version : Int32, @ratchet_every : Int32)
      @ratchet = HmacRatchet.new(initial_hmac_key, @hmac_version, @ratchet_every)
      @mutex = Mutex.new
    end

    def append(event_type : String, actor : String, target_id : UUID?, payload : Hash) : Persistence::AuditEntry
      @mutex.synchronize do
        prev = @persistence.audit.latest_hash
        canonical = canonical_json(event_type, actor, target_id, payload)
        content_hash = HashChain.next_hash(prev, canonical.to_slice)
        hmac = @ratchet.sign(content_hash)

        entry = Persistence::AuditEntry.new(
          seq: 0_i64,
          event_id: UUID.random,
          occurred_at: Time.utc,
          event_type: event_type,
          actor: actor,
          target_id: target_id,
          payload: canonical,
          prev_hash: prev,
          content_hash: content_hash,
          hmac: hmac,
          hmac_key_version: @ratchet.version,
        )
        @persistence.audit.append(entry)
        entry
      end
    end

    def verify_chain : Bool
      latest = @persistence.audit.latest_seq
      return true if latest == 0
      entries = @persistence.audit.range(1_i64, latest)
      return false if entries.size != latest
      pairs = entries.map { |e| {e.prev_hash, e.content_hash} }
      payloads = entries.map(&.payload).map(&.to_slice)
      HashChain.verify(pairs, payloads)
    end

    def ratchet_version : Int32
      @ratchet.version
    end

    private def canonical_json(event_type, actor, target_id, payload) : String
      {
        event_type: event_type,
        actor:      actor,
        target_id:  target_id.try(&.to_s),
        payload:    payload,
      }.to_json
    end
  end
end
