/**
 * Async client compatibility layer.
 *
 * Node's dgram API is event-driven, so Client already provides the same
 * concurrent, Promise-based behavior as pyrad's ClientAsync without needing
 * a separate transport protocol object.
 */
import { Client, type ClientOptions } from './client.js';

export class ClientAsync extends Client {
  constructor(opts: ClientOptions) {
    super(opts);
  }
}
