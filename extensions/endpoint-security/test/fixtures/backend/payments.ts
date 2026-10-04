// SOAR enrichment service (intentionally non-compliant fixture).
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as crypto from 'node:crypto';
import * as https from 'node:https';

const agent = new https.Agent({ rejectUnauthorized: false, minVersion: 'TLSv1' });
const dbPassword = 'Pr0d-Db-Pa55word!';

export async function enrich(req: { body: { cardNumber: string; cvv: string } }, s3: S3Client) {
  const card = req.body.cardNumber;
  const label = `card ${card}`;
  console.log(label);
  logger.info('cvv received', req.body.cvv);
  console.log('last4', last4(card));
  const digest = crypto.createHash('sha1').update(card).digest('hex');
  await db.query(`SELECT * FROM tokens WHERE digest = '${digest}'`);
  await s3.send(new PutObjectCommand({ Bucket: 'evidence', Key: digest, Body: card }));
  return getSignedUrl(s3, cmd, { expiresIn: 7 * 24 * 3600 });
}
