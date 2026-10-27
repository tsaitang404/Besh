import assert from 'node:assert/strict';
import { createHmac, createCipheriv } from 'node:crypto';
import { createDirectionalCipher } from '../packages/ssh-core/src/ciphers.ts';
import { SSHPacketBuilder, SSHPacketParser } from '../packages/ssh-core/src/protocol/packet.ts';
for (const bits of [256,512]) {
 const keys={encKeyClientToServer:new Uint8Array(16).fill(1),ivClientToServer:new Uint8Array(16).fill(2),integrityKeyC2S:new Uint8Array(bits/8).fill(3)};
 const make=()=>createDirectionalCipher({cipherAlgorithm:'aes128-ctr',macAlgorithm:`hmac-sha2-${bits}-etm@openssh.com`,keys,direction:'c2s'});
 const send=await make(), recv=await make(), parser=new SSHPacketParser();
 const reference=createCipheriv('aes-128-ctr',keys.encKeyClientToServer,keys.ivClientToServer);
 for(let seq=0;seq<3;seq++) {
  const payload=new Uint8Array(17+seq).fill(42);
  const wire=await SSHPacketBuilder.build(payload,16,(d,s)=>send.encrypt(d,s),seq,false,(d,s)=>send.sign(d,s),true);
  const framed=wire.subarray(0,-bits/8), tag=wire.subarray(-bits/8), sequence=Buffer.alloc(4);sequence.writeUInt32BE(seq);
  assert.deepEqual(Buffer.from(tag),createHmac(`sha${bits}`,keys.integrityKeyC2S).update(sequence).update(framed).digest());
  const plaintext=reference.update(framed.subarray(4));assert.deepEqual(plaintext.subarray(1,1+payload.length),Buffer.from(payload));
  const next=()=>parser.nextPacket(16,(...a)=>recv.decrypt(...a),false,bits/8,(d,m,s)=>recv.verify(d,m,s),true);
  parser.feed(wire.subarray(0,7));assert.equal(await next(),null);parser.feed(wire.subarray(7));assert.deepEqual((await next()).payload,payload);
 }
 const bad=await SSHPacketBuilder.build(new Uint8Array([1]),16,(d,s)=>send.encrypt(d,s),3,false,(d,s)=>send.sign(d,s),true);bad[5]^=1;
 parser.feed(bad);let decrypted=false;
 await assert.rejects(parser.nextPacket(16,()=>{decrypted=true;throw Error('must not decrypt')},false,bits/8,(d,m,s)=>recv.verify(d,m,s),true),/Invalid packet MAC/);assert.equal(decrypted,false);
 console.log(`PASS SHA-${bits} EtM: independent OpenSSL framing, fragmented stream, counter continuity, reject tampering before decryption`);
}
