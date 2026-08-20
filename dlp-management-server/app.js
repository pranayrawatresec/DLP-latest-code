var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var authRouter = require('./routes/auth');
var sessionsRouter = require('./routes/sessions');
var enrollmentTokensRouter = require('./routes/enrollmentTokens');
var agentsRouter = require('./routes/agents');
var auditRouter = require('./routes/audit');
var protectedRouter = require('./routes/protected');
var incidentsRouter = require('./routes/incidents');
var encryptionRouter = require('./routes/encryption');
var trustedReadersRouter = require('./routes/trustedReaders');
var readDenyPolicyRouter = require('./routes/readDenyPolicy');
var groupsRouter = require('./routes/groups');
var { attachUser } = require('./middleware/auth');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Authentication gate: attaches req.user from the session cookie (or leaves
// it unset). Route-level guards decide what anonymous users may do.
app.use(attachUser);

app.use('/', indexRouter);
app.use('/api/auth', authRouter);
app.use('/api/users', usersRouter);
app.use('/api/sessions', sessionsRouter);
app.use('/api/enrollment-tokens', enrollmentTokensRouter);
app.use('/api/agents', agentsRouter);
app.use('/api/groups', groupsRouter);
app.use('/api/audit', auditRouter);
app.use('/api/protected', protectedRouter);
app.use('/api/incidents', incidentsRouter);
app.use('/api/encryption', encryptionRouter);
app.use('/api/trusted-readers', trustedReadersRouter);
app.use('/api/read-deny-policy', readDenyPolicyRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  var status = err.status || 500;
  if (status >= 500) console.error(err);

  // API routes get JSON, never an HTML error page. Message is generic on 500
  // so internals are not leaked to the client.
  if (req.path.startsWith('/api/')) {
    return res.status(status).json({
      error: status >= 500 ? 'internal error' : err.message
    });
  }

  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};
  res.status(status);
  res.render('error');
});

module.exports = app;
