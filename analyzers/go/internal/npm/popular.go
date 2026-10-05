package npm

// popular lists widely used npm packages that typosquatters imitate.
var popular = []string{
	"react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "moment", "request",
	"async", "bluebird", "underscore", "uuid", "classnames", "prop-types", "yargs", "minimist", "glob", "rimraf",
	"mkdirp", "semver", "fs-extra", "colors", "webpack", "babel-core", "typescript", "eslint", "prettier", "jest",
	"mocha", "chai", "sinon", "dotenv", "body-parser", "cors", "jsonwebtoken", "bcrypt", "bcryptjs", "mongoose",
	"mongodb", "mysql", "mysql2", "pg", "redis", "ioredis", "sequelize", "socket.io", "ws", "node-fetch",
	"cross-fetch", "isomorphic-fetch", "superagent", "got", "ky", "cheerio", "jquery", "vue", "angular", "svelte",
	"rxjs", "zone.js", "tslib", "core-js", "regenerator-runtime", "esbuild", "rollup", "vite", "parcel", "gulp",
	"grunt", "nodemon", "pm2", "concurrently", "cross-env", "inquirer", "ora", "boxen", "figlet", "yaml",
	"js-yaml", "xml2js", "fast-xml-parser", "ini", "toml", "json5", "ajv", "joi", "yup", "zod",
	"validator", "qs", "querystring", "url-parse", "path-to-regexp", "cookie", "cookie-parser", "express-session", "passport", "helmet",
	"morgan", "winston", "pino", "bunyan", "log4js", "date-fns", "dayjs", "luxon", "numeral", "big.js",
	"bignumber.js", "decimal.js", "crypto-js", "node-forge", "elliptic", "ethers", "web3", "sharp", "jimp", "canvas",
	"puppeteer", "playwright", "selenium-webdriver", "electron", "node-gyp", "nan", "bindings", "node-pre-gyp", "prebuild-install", "ffi-napi",
	"vscode-languageclient", "vscode-languageserver", "vscode-jsonrpc", "vscode-uri", "vscode-nls", "@vscode/vsce", "keytar", "chokidar", "micromatch", "minimatch",
	"picomatch", "fast-glob", "globby", "ignore", "anymatch", "braces", "fill-range", "to-regex-range", "is-number", "kind-of",
	"debug", "ms", "supports-color", "has-flag", "ansi-styles", "ansi-regex", "strip-ansi", "string-width", "wrap-ansi", "cliui",
	"escape-string-regexp", "safe-buffer", "inherits", "once", "wrappy", "readable-stream", "string_decoder", "util-deprecate", "event-stream", "through2",
	"tar", "tar-fs", "unzipper", "adm-zip", "jszip", "archiver", "yauzl", "yazl", "follow-redirects", "proxy-agent",
	"http-proxy-agent", "https-proxy-agent", "socks-proxy-agent", "agent-base", "node-ipc", "electron-builder", "discord.js", "telegraf", "openai", "langchain",
}

var popularSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range popular {
		m[p] = true
	}
	return m
}()
