/**
 * Async server compatibility layer.
 *
 * Server is natively event-driven and accepts Promise-returning handlers.
 * These lifecycle aliases mirror pyrad's explicit async transport API.
 */
import { Server, type ServerOptions } from './server.js';

export class ServerAsync extends Server {
  constructor(opts?: ServerOptions) {
    super(opts);
  }

  async initializeTransports(addresses?: string[]): Promise<void> {
    if (addresses) {
      for (const address of addresses) this.bindToAddress(address);
    }
    this.run();
  }

  async deinitializeTransports(): Promise<void> {
    await this.gracefulStop();
  }
}
