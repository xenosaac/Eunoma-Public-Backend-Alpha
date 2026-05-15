import { assertNoForbiddenPlaintextFields } from "@eunoma/deop-protocol";
import type {
  AttestationPartialRequest,
  AttestationPartialResult,
  DepositBindRequest,
  DepositBindResult,
  DkgRoundRequest,
  DkgRoundResult,
  MpccaRoundRequest,
  MpccaRoundResult,
  SessionShareEnvelope,
  WithdrawCAPayloadRequest,
  WithdrawCAPayloadResult,
} from "@eunoma/deop-protocol";
import type {
  CryptoWorker,
  CaRegistrationAggregateRequest,
  CaRegistrationAggregateResult,
  CaRegistrationChallengeRequest,
  CaRegistrationChallengeResult,
  CaRegistrationNonceCommitRequest,
  CaRegistrationNonceCommitResult,
  CaRegistrationPartialRequest,
  CaRegistrationPartialResult,
  DkgCaStartRequest,
  DkgCaStartResult,
  DkgFrostStartRequest,
  DkgFrostStartResult,
  FrostAggregateRequest,
  FrostAggregateResult,
  FrostNonceCommitRequest,
  FrostNonceCommitResult,
  FrostPartialSignRequest,
  FrostPartialSignResult,
  WorkerLocalState,
} from "./types.js";
import { CryptoWorkerUnavailableError } from "./types.js";

export class HttpCryptoWorkerClient implements CryptoWorker {
  constructor(
    private readonly baseUrl: string,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  getLocalState(): Promise<WorkerLocalState> {
    return this.get("/worker/v2/local/state");
  }

  acceptSessionShare(input: SessionShareEnvelope): Promise<{ accepted: true; transcriptHash: string }> {
    return this.post("/worker/v2/session-share", input);
  }

  runDkgRound(input: DkgRoundRequest): Promise<DkgRoundResult> {
    return this.post(`/worker/v2/dkg/${input.protocol}/${input.round}`, input);
  }

  runMpccaRound(input: MpccaRoundRequest): Promise<MpccaRoundResult> {
    return this.post(`/worker/v2/mpcca/${input.protocol}/${input.round}`, input);
  }

  startDkgCa(input: DkgCaStartRequest): Promise<DkgCaStartResult> {
    return this.post("/worker/v2/dkg/ca/start", input);
  }

  startDkgFrost(input: DkgFrostStartRequest): Promise<DkgFrostStartResult> {
    return this.post("/worker/v2/dkg/frost/start", input);
  }

  bindDeposit(input: DepositBindRequest): Promise<DepositBindResult> {
    return this.post("/worker/v2/deposit/bind", input);
  }

  buildWithdrawCAPayload(input: WithdrawCAPayloadRequest): Promise<WithdrawCAPayloadResult> {
    return this.post("/worker/v2/withdraw/ca-payload", input);
  }

  partialAttestation(input: AttestationPartialRequest): Promise<AttestationPartialResult> {
    return this.post("/worker/v2/attestation/partial", input);
  }

  frostNonceCommit(input: FrostNonceCommitRequest): Promise<FrostNonceCommitResult> {
    return this.post("/worker/v2/frost/sign/nonce-commit", input);
  }

  frostPartialSign(input: FrostPartialSignRequest): Promise<FrostPartialSignResult> {
    return this.post("/worker/v2/frost/sign/partial", input);
  }

  frostAggregate(input: FrostAggregateRequest): Promise<FrostAggregateResult> {
    return this.post("/worker/v2/frost/sign/aggregate", input);
  }

  caRegistrationNonceCommit(
    input: CaRegistrationNonceCommitRequest,
  ): Promise<CaRegistrationNonceCommitResult> {
    return this.post("/worker/v2/ca/registration/nonce-commit", input);
  }

  caRegistrationChallenge(input: CaRegistrationChallengeRequest): Promise<CaRegistrationChallengeResult> {
    return this.post("/worker/v2/ca/registration/challenge", input);
  }

  caRegistrationPartial(input: CaRegistrationPartialRequest): Promise<CaRegistrationPartialResult> {
    return this.post("/worker/v2/ca/registration/partial", input);
  }

  caRegistrationAggregate(
    input: CaRegistrationAggregateRequest,
  ): Promise<CaRegistrationAggregateResult> {
    return this.post("/worker/v2/ca/registration/aggregate", input);
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(new URL(path, this.baseUrl), { method: "GET" });
    if (!res.ok) {
      if (res.status === 501 || res.status === 503) {
        throw new CryptoWorkerUnavailableError(`crypto worker ${path} unavailable: ${res.status}`);
      }
      throw new Error(`crypto worker ${path} failed: ${res.status}`);
    }
    return (await res.json()) as T;
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    assertNoForbiddenPlaintextFields(body);
    const res = await this.fetchImpl(new URL(path, this.baseUrl), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      if (res.status === 501 || res.status === 503) {
        throw new CryptoWorkerUnavailableError(`crypto worker ${path} unavailable: ${res.status}`);
      }
      throw new Error(`crypto worker ${path} failed: ${res.status}`);
    }
    return (await res.json()) as T;
  }
}

export class FailClosedCryptoWorker implements CryptoWorker {
  async getLocalState(): Promise<WorkerLocalState> {
    throw new CryptoWorkerUnavailableError();
  }

  async acceptSessionShare(): Promise<{ accepted: true; transcriptHash: string }> {
    throw new CryptoWorkerUnavailableError();
  }

  async runDkgRound(): Promise<DkgRoundResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async runMpccaRound(): Promise<MpccaRoundResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async startDkgCa(): Promise<DkgCaStartResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async startDkgFrost(): Promise<DkgFrostStartResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async bindDeposit(): Promise<DepositBindResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async buildWithdrawCAPayload(): Promise<WithdrawCAPayloadResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async partialAttestation(): Promise<AttestationPartialResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async frostNonceCommit(): Promise<FrostNonceCommitResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async frostPartialSign(): Promise<FrostPartialSignResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async frostAggregate(): Promise<FrostAggregateResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async caRegistrationNonceCommit(): Promise<CaRegistrationNonceCommitResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async caRegistrationChallenge(): Promise<CaRegistrationChallengeResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async caRegistrationPartial(): Promise<CaRegistrationPartialResult> {
    throw new CryptoWorkerUnavailableError();
  }

  async caRegistrationAggregate(): Promise<CaRegistrationAggregateResult> {
    throw new CryptoWorkerUnavailableError();
  }
}
