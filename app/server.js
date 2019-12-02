const Koa = require('koa');
const koaBody = require('koa-body');
const app = new Koa();

// Constants
const PORT = 8440;
const HOST = '0.0.0.0';

// logger

app.use(koaBody());

app.use(async (ctx, next) => {
  await next();
  const rt = ctx.response.get('X-Response-Time');
  console.log(`${ctx.method} ${ctx.url} - ${rt}`);
  console.log(ctx.request.body);
});

// x-response-time

app.use(async (ctx, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  ctx.set('X-Response-Time', `${ms}ms`);
});

// response

app.use(async ctx => {
  ctx.body = 'Hello World';
});

app.listen(PORT, HOST);


console.log(`Listening on http://${HOST}:${PORT}`);