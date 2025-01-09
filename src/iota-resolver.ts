import { Client } from "@iota/sdk-wasm/node";
import {
  type DIDResolutionOptions,
  type DIDDocument,
  type DIDResolutionResult,
} from "did-resolver";
import {
  IotaIdentityClient,
  Resolver,
  CoreDocument,
} from "@iota/identity-wasm/node/index.js";

export class IotaResolver {
  public static getResolver() {
    async function resolve(
      did: string,
      options: DIDResolutionOptions
    ): Promise<DIDResolutionResult> {
      let node = "https://api.stardust-mainnet.iotaledger.net/";

      if (did.includes("did:iota:rms")) {
        node = "https://api.testnet.shimmer.network/";
      }

      const iotaClient = new Client({ localPow: true, primaryNode: node });
      const client = new IotaIdentityClient(iotaClient);

      const resolver = new Resolver({ client });
      const didDoc = (await resolver.resolve(did)) as CoreDocument;

      return {
        didResolutionMetadata: { contentType: "application/did+ld+json" },
        didDocument: JSON.parse(didDoc.toString()) as unknown as DIDDocument,
        didDocumentMetadata: {},
      };
    }

    return { iota: resolve };
  }
}
