import {
  AccessAccept,
  AccessReject,
  Dictionary,
  RemoteHost,
  Server,
  serverOptionsFromEnv,
  type RadiusPacket,
} from 'tsrad';

const dict = new Dictionary(process.env.RADIUS_DICTIONARY ?? '/etc/freeradius/dictionary');

class ExampleServer extends Server {
  handleAuthPacket(packet: RadiusPacket): void {
    const username = packet.getStringAttribute('User-Name');
    const reply = this.createReplyPacket(packet, {
      code: username === 'alice' ? AccessAccept : AccessReject,
    });
    this.sendReply(reply);
  }
}

const options = serverOptionsFromEnv(process.env, {
  dict,
  hosts: new Map([
    ['0.0.0.0', new RemoteHost('0.0.0.0', Buffer.from(process.env.RADIUS_SECRET ?? 'secret'), 'example')],
  ]),
});

const server = new ExampleServer(options);
await server.listen();
console.log('RADIUS server listening');
