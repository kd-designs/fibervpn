import { randomBytes } from 'node:crypto';
import type { FiberClient, FiberCurrency, FiberInvoice, FiberInvoiceStatus } from './types.js';

export const SHANNONS_PER_CKB = 100_000_000n;

export function toHexQuantity(value: bigint): string {
  if (value < 0n) {
    throw new Error('hex quantity must be non-negative');
  }
  return `0x${value.toString(16)}`;
}

interface JsonRpcResponse<T> {
  result?: T;
  error?: { code: number; message: string };
}

interface FnnNewInvoiceResult {
  invoice_address: string;
  invoice: {
    data: {
      payment_hash: string;
    };
  };
}

interface FnnGetInvoiceResult {
  status: FiberInvoiceStatus;
}

export class FnnRpcClient implements FiberClient {
  private nextId = 1;

  constructor(private readonly rpcUrl: string) {}

  private async call<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(this.rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: this.nextId++,
        method,
        params
      })
    });

    if (!res.ok) {
      throw new Error(`FNN RPC HTTP ${res.status}`);
    }

    const payload = (await res.json()) as JsonRpcResponse<T>;
    if (payload.error) {
      throw new Error(`FNN RPC error ${payload.error.code}: ${payload.error.message}`);
    }
    if (payload.result === undefined) {
      throw new Error('FNN RPC returned empty result');
    }
    return payload.result;
  }

  async createInvoice(params: {
    amountShannons: bigint;
    description: string;
    expirySeconds: number;
    currency: FiberCurrency;
  }): Promise<FiberInvoice> {
    const preimage = `0x${randomBytes(32).toString('hex')}`;
    const result = await this.call<FnnNewInvoiceResult>('new_invoice', [
      {
        amount: toHexQuantity(params.amountShannons),
        currency: params.currency,
        description: params.description,
        expiry: toHexQuantity(BigInt(params.expirySeconds)),
        payment_preimage: preimage
      }
    ]);

    return {
      paymentHash: result.invoice.data.payment_hash,
      invoiceAddress: result.invoice_address,
      amountShannons: params.amountShannons,
      status: 'Open'
    };
  }

  async getInvoiceStatus(paymentHash: string): Promise<FiberInvoiceStatus> {
    const result = await this.call<FnnGetInvoiceResult>('get_invoice', [{ payment_hash: paymentHash }]);
    return result.status;
  }
}

export class InMemoryFiberClient implements FiberClient {
  private readonly invoices = new Map<string, FiberInvoice>();

  async createInvoice(params: {
    amountShannons: bigint;
    description: string;
    expirySeconds: number;
    currency: FiberCurrency;
  }): Promise<FiberInvoice> {
    const paymentHash = `0x${randomBytes(32).toString('hex')}`;
    const prefix = params.currency === 'Fibb' ? 'fibb' : 'fibt';
    const invoice: FiberInvoice = {
      paymentHash,
      invoiceAddress: `${prefix}${params.amountShannons.toString(10)}1${paymentHash.slice(2, 26)}`,
      amountShannons: params.amountShannons,
      status: 'Open'
    };
    this.invoices.set(paymentHash, invoice);
    return { ...invoice };
  }

  async getInvoiceStatus(paymentHash: string): Promise<FiberInvoiceStatus> {
    const invoice = this.invoices.get(paymentHash);
    if (!invoice) {
      throw new Error(`unknown payment hash: ${paymentHash}`);
    }
    return invoice.status;
  }

  setInvoiceStatus(paymentHash: string, status: FiberInvoiceStatus): void {
    const invoice = this.invoices.get(paymentHash);
    if (!invoice) {
      throw new Error(`unknown payment hash: ${paymentHash}`);
    }
    invoice.status = status;
  }
}
