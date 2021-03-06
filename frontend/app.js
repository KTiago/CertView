var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var favicon = require('serve-favicon');

var indexRouter = require('./routes/index');
var analysisRouter = require('./routes/analysis');
var certificatesRouter = require('./routes/certificates');

var app = express();
if (app.get('env') === 'development'){
  app.set('port', 3000)
}
app.use(favicon(path.join(__dirname, 'public', 'images','favicon.ico')))

// setup elastic client
var elasticClient = require('./modules/elasticUtil');
elasticClient.connect()

// generate csv files periodically (every minute)
setInterval(elasticClient.generateCSV, 60000);

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/', indexRouter);
app.use('/analysis', analysisRouter);
app.use('/certificates', certificatesRouter);

app.use(express.static(path.join(__dirname, 'public'),{extensions: ['html', 'htm']}));

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  console.log(err.message)
});

module.exports = app;
