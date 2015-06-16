'use strict';

var webpack = require('webpack');
var CompressionPlugin = require("compression-webpack-plugin");

var production = process.env.NODE_ENV == 'production';
var build = process.env.BUILD_ENV == 'build';

var config = {
  target: "web",
  entry: "./src/entry.jsx",
  output: {
    path: './dist/js',
    pathInfo: true,
    publicPath: "/js/",
    filename: "main.js"
  },
  module: {
    loaders: [
      {test: require.resolve("react/addons"), loader: "expose?React"},
      {test: /\.jsx?$/, loaders: ['react-hot', 'babel-loader?experimental&optional=runtime'], exclude: /node_modules/},
      {test: /\.styl$/, loader: 'style!css!stylus?paths=node_modules/'},
      {test: /\.png$/, loader: "url?mimetype=image/png"},
      {test: /\.gif$/, loader: "url?mimetype=image/gif"},
      {test: /\.jpe?g$/, loader: "url?mimetype=image/jpeg"}
    ],
    noParse: /\.min\.js/
  },
  resolve: {
    extentions: ['js', 'jsx', 'styl']
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: JSON.stringify(process.env.NODE_ENV)
      }
    }),
    new webpack.NoErrorsPlugin()
  ]
};

if (production) {
  config.bail = true;
  config.debug = false;
  config.profile = false;
  config.output.pathInfo = false;
  config.devtool = "#source-map";
  config.output.filename = "[name].[hash].min.js";
  config.output.chunkFilename = '[id].js';
  config.plugins = config.plugins.concat([
    new webpack.optimize.DedupePlugin(),
    new webpack.optimize.UglifyJsPlugin({
      mangle: {
        except: ['require', 'export', '$super']
      },
      compress: {
        warnings: false,
        sequences: true,
        dead_code: true,
        conditionals: true,
        booleans: true,
        unused: true,
        if_return: true,
        join_vars: true,
        drop_console: true
      }
    }),
    new CompressionPlugin({
      asset: "{file}.gz",
      algorithm: "gzip",
      regExp: /\.js$|\.html$/,
      threshold: 10240,
      minRatio: 0.8
    })
  ]);
}

if (build) {
  config.plugins = config.plugins.concat([
    function() {
      this.plugin("done", function(stats) {
        var fs = require('graceful-fs');
        fs.readFile('./src/index.html', 'utf8', function (err,data) {
          if (err) return console.log(err);

          if (production) {
            var files = stats.toJson().assets;
            files.forEach(function(file) {
              data = data.replace(file.name.split('.')[0] + '.js', file.name);
            });
          }

          fs.writeFile('./dist/index.html', data, 'utf8', function (err) {
            if (err) return $.util.log(err);
          });
        });
      });
    }
  ]);
}

module.exports = config;