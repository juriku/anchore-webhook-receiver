const Koa = require('koa');
const bodyParser = require('koa-bodyparser');
const Router = require('koa-router');
const fetch = require('node-fetch');
const { IncomingWebhook } = require('@slack/webhook');

// Constants

const PORT = process.env.PORT || 8440;
const HOST = process.env.HOST || '0.0.0.0';
const ANCHORE_USER = process.env.ANCHORE_USER || 'admin';
const ANCHORE_PASS = process.env.ANCHORE_PASS || 'foobar';
const ANCHORE_HOST = process.env.ANCHORE_HOST || 'localhost';
const ANCHORE_PORT = process.env.ANCHORE_PORT || 8228;
const SLACK_URL = process.env.SLACK_WEBHOOK_URL;

const app = new Koa();
const router = new Router();

// logger

app.use(async (ctx, next) => {
  const n = Date.now();
  try {
    await next();
  } catch (err) {
    ctx.status = err.status || 500;
    ctx.body = err.message;
    ctx.app.emit('error', err, ctx);
  }
  console.log(`${new Date(n).toISOString()} - ${Date.now() - n}ms - ${ctx.method} ${ctx.url}`);
});

// response

router.post('/analysis_update', async (ctx) => {
  const json_res = ctx.request.body;
  const image = json_res.data.notification_payload.subscription_key;
  console.log("image: " + image);
  const result = await request_imageId(image);
  const severe = result.filter(x => ['High', 'Critical'].includes(x.severity));
  console.log('length of severe vulns', severe.length);
  const groups = severe.reduce((acc, { vuln, package, feed_group, fix, severity, url }) => {
    acc[package] = acc[package] || { feed_group, vulnerabilities: [] };
    acc[package].vulnerabilities.push({ severity, vuln, fix, url });
    return acc;
  }, {});
  //var formatted_text = Object.entries(groups).map(([ package, { feed_group, vulnerabilities } ]) => {
  //  return `${package} (${feed_group}) count: ${vulnerabilities.length} list: ${vulnerabilities.map(x => `- ${x.severity} (${x.vuln}) -> fix: ${x.fix} `).join(', ')}`
  //});
  if (SLACK_URL){
    await slack_notification(image, groups);
  }
  ctx.body = result;
});

async function request_imageId(image) {
  console.log("requesting imageId for image: " + image);
  const response = await fetch(`http://${ANCHORE_USER}:${ANCHORE_PASS}@${ANCHORE_HOST}:${ANCHORE_PORT}/v1/images`);
  if (!response.ok) {
    console.log(await response.text());
    return;
  }
  const json = await response.json();
  const details = json
    .map(x => x.image_detail[0])
    .find(x => x.fulltag === image);

  return request_vuln(image, details.imageId);
}

async function request_vuln(image, imageId) {
  console.log("requesting vuln for image: " + image + ' with imageId: ' + imageId );
  const response = await fetch(
    `http://${ANCHORE_USER}:${ANCHORE_PASS}@${ANCHORE_HOST}:${ANCHORE_PORT}/v1/images/by_id/${imageId}/vuln/all`
  );
  if (!response.ok) {
    console.log(await response.text());
    return;
  }
  const json = await response.json();
  return json.vulnerabilities;
}

const groupsToAttachments = groups =>
  Object.entries(groups)
    .map(([ package, { feed_group, vulnerabilities }]) => {
      let highestSeverity = 'High';
      const obj = {
        title: `${package} (${feed_group})`,
        fields: vulnerabilities.map(x => {
          if (x.severity === 'Critical' && highestSeverity === 'High') highestSeverity = x.severity;
          return {
            title: x.vuln,
            value: "fix: " + x.fix,
          }
        }),
      };
      obj.color = highestSeverity === 'Critical' ? '#E01E5A' : '#ECB22E';
      return obj;
    });

// Send the notification

async function slack_notification(image, groups) {
  const slack_webhook = new IncomingWebhook(SLACK_URL);
  const attachments = groupsToAttachments(groups);

  await slack_webhook.send({
    username: 'Anchore',
    icon_emoji: ':warning:',
    attachments: [
      {
        color: '#36C5F0',
        title: "CVE vulnerabilities",
        title_link: "https://cve.mitre.org/",
        fields: [
          {
            title: 'Environment',
            value: 'QA',
            short: true
          }
        ]
      },
      {
        color: '#2EB67D',
        fields: [
          {
            title: 'image',
            value: image,
            short: false
          }
        ]
      },
      ...attachments,
    ]
  });
}

app.use(bodyParser());
app.use(router.routes());
app.use(router.allowedMethods());

const server = app.listen(PORT, HOST);
module.exports = server;


console.log(`Listening on http://${HOST}:${PORT}`);