import { AccessAccept, createClientFromEnv, Dictionary } from 'tsrad';

const dict = new Dictionary(process.env.RADIUS_DICTIONARY ?? '/etc/freeradius/dictionary');
const client = createClientFromEnv(process.env, { dict, enforceMA: true });

const request = client.createAuthPacket();
request.setUserName(process.env.RADIUS_USERNAME ?? 'alice');
request.setPassword(process.env.RADIUS_PASSWORD ?? 'secret');

try {
  const reply = await client.sendPacket(request);
  console.log(reply.code === AccessAccept ? 'accepted' : 'rejected', reply.code);
} finally {
  client.close();
}
