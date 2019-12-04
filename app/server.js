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
const SLACK_URL = process.env.SLACK_WEBHOOK_URL

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
  const groups = severe.reduce((acc, { vuln, package, feed_group, fix, severity }) => {
    acc[package] = acc[package] || { feed_group, vulnerabilities: [] };
    acc[package].vulnerabilities.push({ severity, vuln, fix });
    return acc;
  }, {});
  console.dir(groups, { depth: null });
  var formatted_text = Object.entries(groups).map(([ package, { feed_group, vulnerabilities } ]) => {
    return `${package} (${feed_group}) count: ${vulnerabilities.length} list: ${vulnerabilities.map(x => `- ${x.severity} (${x.vuln}) -> fix: ${x.fix} `).join(', ')}`
  });
  //console.log(formatted_text);
  if (SLACK_URL){
    await slack_notification(image, formatted_text);
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

// Send the notification

async function slack_notification(image, text) {
  const slack_webhook = new IncomingWebhook(SLACK_URL);
  await slack_webhook.send({
    username: 'Anchore vulnerabilities alert', // This will appear as user name who posts the message
    text: JSON.stringify(text, null, "\t"), // text
    icon_emoji: ':warning:', // User icon, you can also use custom icons here
    attachments: [{ // this defines the attachment block, allows for better layout usage
      color: '#eed140', // color of the attachments sidebar.
      fields: [ // actual fields
        {
          title: 'Environment', // Custom field
          value: 'QA', // Custom value
          short: true // long fields will be full width
        },
        {
          title: 'image', // Custom field
          value: image, // Custom value
          short: true // long fields will be full width
        }
      ]
    }]
    });
}

app.use(bodyParser());
app.use(router.routes());
app.use(router.allowedMethods());

const server = app.listen(PORT, HOST);
module.exports = server;


console.log(`Listening on http://${HOST}:${PORT}`);