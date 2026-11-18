/**
 * What the SDK's owner workflows need from Stellar: the network's record of a transaction, the record of an expired
 * signed step, the steps of a Native wallet account's setup and the owner's approval of a Native policy. The SDK holds
 * the workflows, their journal and their recovery rules; these hooks build, send and read Stellar transactions and
 * check Stellar signatures.
 */
import type { OwnerChain } from '@allowit/core';
/** The hooks of the SDK's owner workflows: Core's `OwnerChain` contract. */
export declare const ownerChain: OwnerChain;
