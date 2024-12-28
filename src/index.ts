import {
  IdentityAccountProps,
  CreateDidProps,
  DidCreationResult,
  NetworkAdapter,
  NetworkAdapterOptions,
  CredentialsManager,
  StorageSpec,
  IdentityConfig,
  bytesToString,
  stringToBytes,
  IdentityAccount,
  DidSigner,
} from "@tanglelabs/ssimon";
import Module from "node:module";
const require = Module.createRequire(import.meta.url);
import { getPublicKeyAsync } from "@noble/ed25519";
import { IotaJwkStore, IotaKidStore } from "./iota-store";
const { Client, SecretManager, Utils } = require("@iota/sdk-wasm/node");
const {
  IotaDID,
  IotaDocument,
  IotaIdentityClient,
  JwsAlgorithm,
  MethodScope,
  Storage,
} = require("@iota/identity-wasm/node");
import * as didJWT from "did-jwt";
import { ensureAddressHasFunds } from "./utils";
import { Resolver } from "did-resolver";
import { MethodDigest, VerificationMethod } from "@iota/identity-wasm/node";

export class DidIotaAdapter<K extends StorageSpec<Record<string, any>, any>>
  implements NetworkAdapter
{
  store: StorageSpec<any, any>;
  resolver: Resolver;

  private constructor() {}

  getMethodIdentifier(): string {
    return "iota";
  }

  public static async build(options: NetworkAdapterOptions) {
    const adapter = new DidIotaAdapter();
    adapter.store = options.driver;
    adapter.resolver = options.resolver;
    return adapter;
  }

  public async createDid(props: CreateDidProps): Promise<DidCreationResult> {
    const { store, seed, alias } = props;
    const generatedSeed = seed
      ? seed
      : Utils.mnemonicToHexSeed(Utils.generateMnemonic())
          .split("0x")[1]
          .substring(0, 64);
    const config = await this.store.findOne({ alias });
    const identity = await this.buildIotaAccount({
      seed: config.seed ?? seed ?? generatedSeed,
      isOld: !!seed,
      alias: props.alias,
      store: store,
      extras: {
        storage: this.store,
      },
    });
    return {
      identity,
      seed: generatedSeed,
    };
  }

  public async deserializeDid<T extends StorageSpec<Record<string, any>, any>>(
    config: IdentityConfig,
    store: T
  ): Promise<DidCreationResult> {
    const identity = await this.buildIotaAccount({
      seed: config.seed as string,
      isOld: true,
      alias: config.alias,
      store: store,
      did: config.did,
      extras: {
        storage: this.store,
      },
    });

    return { identity, seed: config.seed as string };
  }

  public async buildIotaAccount(
    props: IdentityAccountProps<StorageSpec<any, any>> & { did?: string }
  ) {
    const { seed, isOld, store, extras, alias, did } = props;
    const { storage } = extras;

    const publicKey = bytesToString(
      await getPublicKeyAsync(stringToBytes(seed))
    );
    const hexSeed = "0x" + seed + publicKey;
    const API_ENDPOINT = "https://api.stardust-mainnet.iotaledger.net";
    const client = new Client({
      primaryNode: API_ENDPOINT,
      localPow: true,
    });
    const didClient = new IotaIdentityClient(client);

    // Get the Bech32 human-readable part (HRP) of the network.
    const networkHrp: string = await didClient.getNetworkHrp();

    const seedSecretManager = {
      hexSeed,
    };

    // Generate a random mnemonic for our wallet.
    const secretManager = new SecretManager(seedSecretManager);

    const walletAddressBech32 = (
      await secretManager.generateEd25519Addresses({
        accountIndex: 0,
        range: {
          start: 0,
          end: 1,
        },
        bech32Hrp: networkHrp,
      })
    )[0];

    const identity = new IdentityAccount();

    const jwkStore = await IotaJwkStore.build(storage, alias);
    const kidStore = await IotaKidStore.build(storage, alias);

    const iotaStorage: Storage = new Storage(jwkStore, kidStore);

    let document: Record<string, any>;
    if (!isOld) {
      document = new IotaDocument(networkHrp);
      await document.generateMethod(
        iotaStorage,
        IotaJwkStore.ed25519KeyType(),
        JwsAlgorithm.EdDSA,
        "#key-1",
        MethodScope.VerificationMethod()
      );
      const address = Utils.parseBech32Address(walletAddressBech32);
      const aliasOutput = await didClient.newDidOutput(address, document);

      await ensureAddressHasFunds(
        client,
        walletAddressBech32,
        aliasOutput.amount,
        seed
      );
      const publishedDoc = await didClient.publishDidOutput(
        seedSecretManager,
        aliasOutput
      );
      document = JSON.parse(publishedDoc);
    } else {
      document = await didClient.resolveDid(IotaDID.parse(did));
    }

    document = JSON.parse(JSON.stringify(document));

    const verificationMethod = VerificationMethod.fromJSON(
      document.verificationMethod[0]
    );
    const methodDigest = new MethodDigest(verificationMethod);
    const keyId = await kidStore.getKeyId(methodDigest);
    const privateKeyHex = await jwkStore.getPrivateKeyFromStore(keyId);

    const iotaEdDSASigner = didJWT.EdDSASigner(privateKeyHex);

    const signer: DidSigner = {
      signer: iotaEdDSASigner,
      kid: `did#key-1` as `did:${string}`,
      did: did as `did:${string}`,
      alg: "EdDSA",
    };
    identity.document = JSON.parse(JSON.stringify(document));
    const credentialsManager = CredentialsManager.build(
      store,
      signer,
      this.resolver
    );
    identity.credentials = credentialsManager;
    identity.signer = signer;

    return identity;
  }
}

export * from "./iota-store";
export * from "./iota-resolver";
