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
const FIX_VALUE_IGNORE = process.env.FIX_VALUE_IGNORE;

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
  ctx.status = 200;
  try {
    const image = json_res.data.notification_payload.subscription_key;
    console.log("image: " + image);
    const result = await request_imageId(image);
    console.log(result);
    const severe = result.filter(x => ['High', 'Critical'].includes(x.severity));
    console.log(severe);
    console.log('length of severe vulns', severe.length);
    const groups = severe.reduce((acc, { vuln, package, feed_group, fix, severity, url }) => {
      acc[vuln] = acc[vuln] || { feed_group, url, vulnerabilities: [] };
      acc[vuln].vulnerabilities.push({ severity, package, fix });
      return acc;
    }, {});
    //var formatted_text = Object.entries(groups).map(([ package, { feed_group, vulnerabilities } ]) => {
    //  return `${package} (${feed_group}) count: ${vulnerabilities.length} list: ${vulnerabilities.map(x => `- ${x.severity} (${x.vuln}) -> fix: ${x.fix} `).join(', ')}`
    //});
    if (SLACK_URL && severe.length !== 0){
      await slack_notification(image, groups);
    }
  } catch (err) {
    console.log(err);
    if (SLACK_URL){
      slack_error(err);
    }
  }
});

// simple health check
router.get('/heath', async (ctx) => {
  ctx.body = 'heatlh';
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

// const groupsToAttachments = groups =>
//   Object.values(groups)
//     .map(({ feed_group, package, fix, url, vuln, severity }) => {
//       let highestSeverity = 'High';
//       var checkVuln;
//       if (fix !== 'None') {
//         if (vuln !== checkVuln) {
//           checkVuln = vuln;
//           if (severity === 'Critical' && highestSeverity === 'High') highestSeverity = severity;
//           var color = highestSeverity === 'Critical' ? '#E01E5A' : '#ECB22E'
//           const obj = {
//             title: vuln,
//             title_link: url,
//             text: "fix: " + fix,
//             pretext: `${package} (${feed_group})`,
//             color: color,
//         };
//         return obj;
//       };
//       };
//     });

const groupsToAttachments = groups =>
  Object.entries(groups)
    .map(([ vuln, { feed_group, url, vulnerabilities }]) => {
      let highestSeverity = 'High';
      let fixFound = false;
      const obj = {
        title: `${vuln} (${feed_group})`,
        title_link: url,
        fields: vulnerabilities.map(x => {
          if (x.severity === 'Critical' && highestSeverity === 'High') highestSeverity = x.severity;
          if (x.fix !== FIX_VALUE_IGNORE) {
            fixFound = true
            return {
              title: x.package,
              value: "fix: " + x.fix,
              }
          };
        }),
      };
      obj.color = highestSeverity === 'Critical' ? '#E01E5A' : '#ECB22E';
      if (fixFound === true) return obj;
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

async function slack_error(err) {
  const slack_webhook = new IncomingWebhook(SLACK_URL);
  var strErr = err.toString();

  await slack_webhook.send({
    username: 'Anchore',
    icon_emoji: ':warning:',
    attachments: [
      {
        color: '#E01E5A',
        title: "Error while processing information",
        fields: [
          {
            title: 'Error:',
            value: strErr,
            short: false
          }
        ]
      },
    ]
  });
}

app.use(bodyParser());
app.use(router.routes());
app.use(router.allowedMethods());

const server = app.listen(PORT, HOST);
module.exports = server;


console.log(`Listening on http://${HOST}:${PORT}`);