# ===================
# ©AngelaMos | 2026
# rotation_orchestrator.cr
# ===================

require "log"
require "uuid"
require "./event_bus"
require "../events/credential_events"
require "../rotators/rotator"
require "../persistence/persistence"
require "../persistence/repos"

module CRE::Engine
  class VerifyFailed < Exception; end

  class RotationOrchestrator
    Log = ::Log.for("cre.rotator")

    def initialize(@bus : EventBus, @persistence : Persistence::Persistence)
    end

    def run(c : Domain::Credential, rotator : Rotators::Rotator) : Persistence::RotationState
      rotation_id = UUID.random
      record = Persistence::RotationRecord.new(
        id: rotation_id,
        credential_id: c.id,
        rotator_kind: kind_to_enum(rotator.kind),
        state: Persistence::RotationState::Generating,
        started_at: Time.utc,
        completed_at: nil,
        failure_reason: nil,
      )
      @persistence.rotations.insert(record)
      @bus.publish Events::RotationStarted.new(c.id, rotation_id, rotator.kind.to_s)

      new_secret = nil
      current_step = :generate
      begin
        @bus.publish Events::RotationStepStarted.new(c.id, rotation_id, :generate)
        new_secret = rotator.generate(c)
        @persistence.rotations.update_state(rotation_id, Persistence::RotationState::Applying)
        @bus.publish Events::RotationStepCompleted.new(c.id, rotation_id, :generate)

        current_step = :apply
        @bus.publish Events::RotationStepStarted.new(c.id, rotation_id, :apply)
        rotator.apply(c, new_secret)
        @persistence.rotations.update_state(rotation_id, Persistence::RotationState::Verifying)
        @bus.publish Events::RotationStepCompleted.new(c.id, rotation_id, :apply)

        current_step = :verify
        @bus.publish Events::RotationStepStarted.new(c.id, rotation_id, :verify)
        ok = rotator.verify(c, new_secret)
        raise VerifyFailed.new("verify returned false") unless ok
        @persistence.rotations.update_state(rotation_id, Persistence::RotationState::Committing)
        @bus.publish Events::RotationStepCompleted.new(c.id, rotation_id, :verify)

        current_step = :commit
        @bus.publish Events::RotationStepStarted.new(c.id, rotation_id, :commit)
        rotator.commit(c, new_secret)
        @persistence.rotations.update_state(rotation_id, Persistence::RotationState::Completed)
        @bus.publish Events::RotationStepCompleted.new(c.id, rotation_id, :commit)

        @bus.publish Events::RotationCompleted.new(c.id, rotation_id)
        Persistence::RotationState::Completed
      rescue ex
        if ns = new_secret
          if current_step == :apply || current_step == :verify
            begin
              rotator.rollback_apply(c, ns)
            rescue rb
              Log.error(exception: rb) { "rollback_apply failed for credential #{c.id}" }
            end
          end
        end
        @persistence.rotations.update_state(rotation_id, Persistence::RotationState::Failed, ex.message || ex.class.name)
        @bus.publish Events::RotationStepFailed.new(c.id, rotation_id, current_step, ex.message || ex.class.name)
        @bus.publish Events::RotationFailed.new(c.id, rotation_id, ex.message || ex.class.name)
        Persistence::RotationState::Failed
      end
    end

    private def kind_to_enum(kind : Symbol) : Persistence::RotatorKind
      case kind
      when :aws_secretsmgr then Persistence::RotatorKind::AwsSecretsmgr
      when :vault_dynamic  then Persistence::RotatorKind::VaultDynamic
      when :github_pat     then Persistence::RotatorKind::GithubPat
      when :env_file       then Persistence::RotatorKind::EnvFile
      else                      raise "unknown rotator kind #{kind}"
      end
    end
  end
end
