# ===================
# ©AngelaMos | 2026
# rotation_orchestrator_spec.cr
# ===================

require "../../spec_helper"
require "../../../src/cre/engine/rotation_orchestrator"
require "../../../src/cre/persistence/sqlite/sqlite_persistence"
require "../../../src/cre/rotators/env_file"

private def drain(ch : ::Channel(CRE::Events::Event)) : Array(CRE::Events::Event)
  out = [] of CRE::Events::Event
  loop do
    select
    when ev = ch.receive
      out << ev
    else
      break
    end
  end
  out
end

private def env_credential(path : String, key : String) : CRE::Domain::Credential
  CRE::Domain::Credential.new(
    id: UUID.random,
    external_id: "#{path}::#{key}",
    kind: CRE::Domain::CredentialKind::EnvFile,
    name: key,
    tags: {"path" => path, "key" => key} of String => String,
  )
end

describe CRE::Engine::RotationOrchestrator do
  it "publishes the full event sequence on success" do
    tmp = File.tempfile("cre_rot_") { |f| f << "K=v\n" }
    cred = env_credential(tmp.path, "K")

    persist = CRE::Persistence::Sqlite::SqlitePersistence.new(":memory:")
    persist.migrate!
    persist.credentials.insert(cred)

    bus = CRE::Engine::EventBus.new
    ch = bus.subscribe
    bus.run

    orchestrator = CRE::Engine::RotationOrchestrator.new(bus, persist)
    state = orchestrator.run(cred, CRE::Rotators::EnvFileRotator.new)

    sleep 0.1.seconds
    state.completed?.should be_true

    events = drain(ch).map(&.class.name)
    events.should contain "CRE::Events::RotationStarted"
    events.count("CRE::Events::RotationStepCompleted").should eq 4
    events.should contain "CRE::Events::RotationCompleted"
    events.should_not contain "CRE::Events::RotationFailed"

    # rotation row recorded as completed
    persist.rotations.in_flight.size.should eq 0
  ensure
    bus.try(&.stop)
    persist.try(&.close)
    tmp.try(&.delete)
  end

  it "handles a rotator that raises during apply via rollback" do
    tmp = File.tempfile("cre_rot_fail_") { |f| f << "K=v\n" }
    cred = env_credential(tmp.path, "K")

    persist = CRE::Persistence::Sqlite::SqlitePersistence.new(":memory:")
    persist.migrate!
    persist.credentials.insert(cred)

    bus = CRE::Engine::EventBus.new
    ch = bus.subscribe
    bus.run

    failing = FailingRotator.new
    state = CRE::Engine::RotationOrchestrator.new(bus, persist).run(cred, failing)
    sleep 0.1.seconds

    state.failed?.should be_true
    failing.rolled_back.should be_true

    events = drain(ch).map(&.class.name)
    events.should contain "CRE::Events::RotationStepFailed"
    events.should contain "CRE::Events::RotationFailed"
  ensure
    bus.try(&.stop)
    persist.try(&.close)
    tmp.try(&.delete)
  end
end

class FailingRotator < CRE::Rotators::Rotator
  property rolled_back = false

  def kind : Symbol
    :env_file
  end

  def can_rotate?(c : CRE::Domain::Credential) : Bool
    _ = c
    true
  end

  def generate(c : CRE::Domain::Credential) : CRE::Domain::NewSecret
    _ = c
    CRE::Domain::NewSecret.new(ciphertext: "x".to_slice)
  end

  def apply(c : CRE::Domain::Credential, s : CRE::Domain::NewSecret) : Nil
    _ = {c, s}
    raise CRE::Rotators::RotatorError.new("apply boom")
  end

  def verify(c : CRE::Domain::Credential, s : CRE::Domain::NewSecret) : Bool
    _ = {c, s}
    true
  end

  def commit(c : CRE::Domain::Credential, s : CRE::Domain::NewSecret) : Nil
    _ = {c, s}
  end

  def rollback_apply(c : CRE::Domain::Credential, s : CRE::Domain::NewSecret) : Nil
    _ = {c, s}
    @rolled_back = true
  end
end
