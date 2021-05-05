#!/usr/bin/env node
import path from "path";
import process from "process";
import os from "os";
import fs from "fs-extra";
import yargs from "yargs";
import Mustache from "mustache";
import {Worker} from "worker_threads";
import {Buffer} from "buffer";
import {Readable} from "stream";
import cluster from "cluster";
import crypto from "crypto";
import {fileURLToPath} from "url";
import Fastify from "fastify";
import FastifyStatic from "fastify-static";
import FastifyCookie from "fastify-cookie";
import fetch from "node-fetch";
import logger from "./logger.mjs";
import $yaml from "yaml";
import modifyCase from "./modify-case.mjs";
import winston from "winston";
import toJson from "json-stringify-safe";

const uniq = (uniqLength) => Array(uniqLength).fill(0).map(x => Math.random().toString(36).charAt(2)).map(ch => Math.random() > 0.5 ? ch.toUpperCase() : ch.toLowerCase()).join("");

const traceIdLength = 26;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const cwd = process.cwd();
const packageDir = getPackageDir();
const serverDir = path.join(packageDir, "server");
const staticDir = path.join(packageDir, "static");
const pkg = getJSON("./package.json");

const health = {
	graylogActive: false,
	consulActive: false,
	webServerActive: false,
};

const envPrefix = `${pkg.name.replace("-", "_").toUpperCase()}_APP`;

async function getConsulKV (host, port, key, token) {
	const url = new URL(host);
	if (port) {
		url.port = port;
	}
	url.pathname = path.posix.join(`/v1/kv/`, key);
	const content = await (await fetch(url.toString(), {
		headers: {
			"x-consul-token": token,
			"accept": "application/json",
		},
	})).json();
	const value = content?.[0]?.Value;
	const text = Buffer.from(value, "base64").toString("utf8");
	const result = $yaml.parse(text);

	return result;
}

async function init (nested = false) {
	if (!nested) {
		if (!process.env[`${envPrefix}_GL_START`]) {
			const gl_address = Object.entries(process.env).find(([key, value]) => key.toLowerCase() === "gl_address")?.[1];
			const gl_port = Object.entries(process.env).find(([key, value]) => key.toLowerCase() === "gl_port")?.[1];
			const gl_start = Object.entries(process.env).find(([key, value]) => key.toLowerCase() === "gl_start")?.[1];
			const gl_proto = Object.entries(process.env).find(([key, value]) => key.toLowerCase() === "gl_proto")?.[1];
			if (gl_address) {
				process.env[`${envPrefix}_GL_ADDRESS`] = gl_address;
			}
			if (gl_port) {
				process.env[`${envPrefix}_GL_PORT`] = gl_port;
			}
			if (gl_start) {
				process.env[`${envPrefix}_GL_START`] = gl_start;
			}
			process.env[`${envPrefix}_GL_PROTO`] = gl_proto || "udp";
		}

		if ((process.env[`${envPrefix}_GL_START`] || "false").toLowerCase() === "true") {
			console.log(`using graylog as logger`, {
				protocol: process.env[`${envPrefix}_GL_PROTO`],
				host: process.env[`${envPrefix}_GL_ADDRESS`],
				port: process.env[`${envPrefix}_GL_PORT`],
			});

			const WinstonGelf = (await import("winston-gelf")).default;
			const transport = new WinstonGelf({
				handleExceptions: true,
				gelfPro: {
					adapterName: process.env[`${envPrefix}_GL_PROTO`],
					adapterOptions: {
						host: process.env[`${envPrefix}_GL_ADDRESS`],
						port: process.env[`${envPrefix}_GL_PORT`],
					},
				},
			});

			transport.__name$ = "graylog";
			logger.add(transport);
			health.graylogActive = true;

			logger.defaultMeta["app-name"] = pkg.name;
			logger.defaultMeta["app-version"] = pkg.version;
		}
		else {
			const transport = new winston.transports.Console({
				handleExceptions: true,
				format: winston.format.combine(
					winston.format.colorize(),
					winston.format.simple()
				),
			});

			transport.__name$ = "console";
			logger.add(transport);
		}

		logger.log({level: "http", message: `env prefix is: ${envPrefix}`});
	}


	const argv = await yargs(process.argv.slice(2))
		.parserConfiguration({"strip-aliased": true})
		.command([
			{
				command: "start [port] [host] [backendUrl]",
				aliases: ["s"],
				describe: "start node server",
				handler: async argv => {

					if (!nested && argv["consul-kv"]) {
						logger.log({level: "info", message: "loading consul config..."});
						try {
							const data = await getConsulKV(argv["consul-host"], argv["consul-port"], argv["consul-kv"], argv["consul-token"]);
							Object.entries(data).forEach(([key, value]) => {
								const k = envPrefix + "_" + modifyCase(key, {format: "const", breakByCase: true});
								process.env[k] = value;
							});
							health.consulActive = true;
							try {
								await init(true);
							}
							catch (error) {
								logger.log({level: "error", message: `error initializing web server: ${error.message}`});
								health.error = error;
							}
						}
						catch (error) {
							logger.log({level: "error", message: `error loading config from consul: ${error.message}`});
							health.consulActive = false;
							health.error = error;
						}
					}
					else {
						logger.log({level: "info", message: `app settings is: ${toJson(argv)}`});

						const transports = {
							console: logger.transports.find(t => t.__name$ === "console"),
							graylog: logger.transports.find(t => t.__name$ === "graylog"),
						};

						if (transports.graylog) {
							logger.log({level: "info", message: `graylog - log level is: ${argv["gl-level"]}`});
							transports.graylog.level = argv["gl-level"];
						}
						else {
							logger.log({level: "info", message: `graylog - cant find logger transport by name`});
						}

						if (transports.console) {
							logger.log({level: "info", message: `console - log level is: ${argv["log-level"]}`});
							transports.console.level = argv["log-level"];
						}

						logger.log({level: "info", message: "starting app..."});
						await startCluster(argv);
					}
				},
				builder: yargs => {
					return yargs
						.env(envPrefix)
						.positional("http2", {
							describe: "use http2",
							type: "boolean",
							default: false,
						})
						.positional("https", {
							describe: "use https",
							type: "boolean",
							default: false,
						})
						.positional("secure-key", {
							describe: "ssl key for https",
							type: "string",
						})
						.positional("secure-cert", {
							describe: "ssl cert for https",
							type: "string",
						})
						.positional("backend-url", {
							alias: ["b"],
							describe: "backend server origin url",
							type: "string",
						})
						.positional("trust-proxy", {
							alias: ["t"],
							describe: "use behind reverse proxy",
							type: "boolean",
							default: true,
						})
						.positional("port", {
							alias: ["p"],
							describe: "server port",
							type: "number",
							default: 3000,
						})
						.positional("host", {
							alias: ["h"],
							describe: "server host or ip",
							type: "string",
							default: "0.0.0.0",
						})
						.positional("consul-host", {
							describe: "consul host",
							type: "string",
						})
						.positional("consul-port", {
							describe: "consul port",
							type: "number",
						})
						.positional("consul-token", {
							describe: "consul token",
							type: "string",
						})
						.positional("consul-kv", {
							describe: "consul kv key",
							type: "string",
						})
						.positional("gl-address", {
							describe: "graylog host",
							type: "string",
						})
						.positional("gl-port", {
							describe: "graylog port",
							type: "number",
							// default: undefined,
						})
						.positional("gl-start", {
							describe: "graylog enabled",
							type: "boolean",
						})
						.positional("gl-proto", {
							describe: "graylog protocol",
							type: "string",
							default: "udp",
						})
						.positional("gl-level", {
							describe: "graylog log level",
							type: "string",
							default: "info",
						})
						.positional("log-level", {
							describe: "log level",
							type: "string",
							default: "info",
						})
						.positional("letsencrypt-dir", {
							describe: "letsencrypt directory",
							type: "string",
						})
						.positional("multiprocess", {
							alias: ["multi"],
							describe: "use nodejs cluster",
							type: "number",
							default: 0,
						});
				},
			},
		])
		.help("help")
		.demandCommand()
		.showHelpOnFail(true)
		.argv;
}

async function startServer (argv) {
	logger.log({level: "info", message: `http2 ${argv.http2}`});
	logger.log({level: "info", message: `https ${argv.https}`});
	logger.log({level: "info", message: `trustProxy ${argv["trust-proxy"]}`});
	logger.log({level: "info", message: `backendUrl ${argv["backend-url"]}`});
	const sslOptions = {};
	if (argv["secure-key"]) {
		sslOptions.key = fs.readFileSync(argv["secure-key"]);
		console.log("sslOptions.key", sslOptions.key);
	}
	if (argv["secure-cert"]) {
		sslOptions.cert = fs.readFileSync(argv["secure-cert"]);
		console.log("sslOptions.cert", sslOptions.cert);
	}


	const fastify = Fastify(Object.assign({
		trustProxy: argv["trust-proxy"],
		http2: argv.http2,
		https: argv.https ? sslOptions : false,
	}, {}));

	const indexTemplate = await fs.readFile(path.join(serverDir, "templates/index.mustache"), "utf8");
	Mustache.parse(indexTemplate);

	fastify.addHook("onSend", (request, reply, payload, next) => {
		if (request.cookies.traceId) {
			reply.header("trace-id", request.cookies.traceId);
		}
		let requestBody;
		if (typeof request.body === "string") {
			requestBody = request.body;
		}
		let responseBody;
		if (typeof payload === "string") {
			responseBody = payload;
		}
		const traceId = request?.headers?.["trace-id"] || reply?.headers?.["trace-id"] || request?.cookies?.traceId || reply?.cookies?.traceId;
		logger.log({
			message: `response to ${request.method} ${request.url}`,
			level: "http",
			type: "response",
			url: request.url,
			ip: request.ip,
			traceId,
			method: request.method,
			requestBody,
			responseBody,
		});

		reply.header("x-content-type-options", "nosniff");
		next(null, payload);
	});

	fastify.addHook("preParsing", (request, reply, payload, next) => {
		let requestBody;
		if (typeof request.body === "string") {
			requestBody = request.body;
		}

		const traceId = request?.headers?.["trace-id"] || reply?.headers?.["trace-id"] || request?.cookies?.traceId || reply?.cookies?.traceId;

		logger.log({
			message: `request to ${request.method} ${request.url}`,
			level: "http",
			type: "request",
			url: request.url,
			ip: request.ip,
			traceId,
			method: request.method,
			requestBody,
		});
		next(null, payload);
	});

	fastify.setNotFoundHandler(async (reqest, reply) => {
		try {
			const nonce = crypto.randomBytes(16).toString("base64");
			const csrfToken = uniq(26);
			const traceId = uniq(26);
			const renderedTemplate = Mustache.render(indexTemplate, {nonce, csrfToken, traceId});
			reply
				.code(200)
				.cookie("csrfToken", csrfToken, {
					secure: true,
					httpOnly: true,
				})
				.cookie("traceId", traceId, {
					secure: true,
					httpOnly: true,
				})
				.headers(Object.assign({}, {
					"trace-id": traceId,
					"content-type": "text/html",
					"content-security-policy":
					"script-src 'self' https: http: 'unsafe-inline' 'nonce-" + nonce + "' 'strict-dynamic'; "
					+ "worker-src 'self';"
					+ "manifest-src 'self' 'nonce-" + nonce + "';"
					+ "media-src 'self' 'nonce-" + nonce + "';"
					+ "object-src 'none';"
					+ "frame-ancestors 'self';"
					+ "base-uri 'self' 'nonce-" + nonce + "';",
					"x-frame-options": "SAMEORIGIN",
					"x-xss-protection": "1",
				}))
				.send(renderedTemplate);
		}
		catch (error) {
			logger.log({level: "error", message: error.message});
			reply.code(500).send();
		}
	});
	fastify.get("/health", async (request, reply) => {
		if (health.error) { // fail
			reply.code(500).headers({"content-type": "application/json"}).send(toJson(health));
		}
		else { // success
			reply.code(200).headers({"content-type": "application/json"}).send(toJson(health));
		}
	});

	fastify.post("/api/users", async (request, reply) => {
		try {
			// if (!request.cookies.csrfToken || request.cookies.csrfToken !== request.headers["x-csrf-token"]) {
			// 	reply.code(403).send({errCode: "CSRF_MISSMATCH_ERROR", errText: "CSRF Token Mismatch"});
			// 	return;
			// }
			const traceId = uniq(traceIdLength);
			const url = new URL(argv["backend-url"] || "https://api.github.com");
			// const body = JSON.stringify(request.body);
			url.pathname = `/users`;

			logger.log({level: "info", message: `proxy request to ${url.toString()}`, content: request.body});
			const response = await fetch(url.toString(), {
				method: "GET",
				// body,
				headers: {
					"accept": "application/json",
					"content-type": "application/json",
					"trace-id": traceId,
				},
			});
			const data = await response.json();

			reply.code(response.status);
			reply.headers({
				"content-type": response.headers.get("content-type"),
				"trace-id": traceId,
			});
			reply.send(data);
		}
		catch (error) {
			logger.log({level: "error", message: error.message});
			reply.code(500).send({errText: error.message});
		}
	});

	fastify.register(FastifyStatic, {
		root: staticDir,
		dotfiles: "allow",
		// setHeaders (response, path, stat) {
		// 	// console.log("path", path);
		// 	// console.log("stat", stat);
		// 	response.setHeader("trace-id", "nosniff");
		// 	response.setHeader("x-content-type-options", "nosniff");
		// }
	});
	if (argv["letsencrypt-dir"]) {
		logger.log({level: "info", message: `path: ${path.join(argv["letsencrypt-dir"], "/.well-known/acme-challenge")}`});
		fastify.register(FastifyStatic, {
			root: path.join(argv["letsencrypt-dir"], "/.well-known/acme-challenge"),
			prefix: "/.well-known/acme-challenge",
			decorateReply: false,
			dotfiles: "allow",
			// setHeaders (response, path, stat) {
			// 	// console.log("path", path);
			// 	// console.log("stat", stat);
			// 	response.setHeader("trace-id", "nosniff");
			// 	response.setHeader("x-content-type-options", "nosniff");
			// }
		});
	}
	fastify.register(FastifyCookie);

	const port = argv.port;
	const host = argv.host;
	try {
		fastify.listen(port, host, (error, address) => {
			if (error) {
				health.error = error;
			}
			else {
				health.webServerActive = true;
			}
			if (cluster.isMaster) {
				logger.log({level: "info", message: `${pkg.name} - server listening on ${address}`});
			}
			else {
				logger.log({level: "info", message: `${pkg.name} - subprocess(${process.pid}) of server(${process.ppid}) listening on ${address}`});
			}
		});
	}
	catch (error) {
		health.webServerActive = false;
		health.error = error;
	}
}

async function startCluster (argv) {
	const multi = argv.multiprocess;
	const cpuAmountMax = os.cpus().length;
	let cpuAmount;
	if (!multi) {
		cpuAmount = 0;
	}
	else if (multi < 0) {
		cpuAmount = cpuAmountMax + multi;
	}
	else if (multi > 0 && multi <= 1) {
		cpuAmount = Math.ceil(cpuAmountMax * multi);
	}
	else {
		cpuAmount = multi;
	}
	cpuAmount = Math.max(1, Math.min(cpuAmountMax, Math.round(cpuAmount)));
	if (cluster.isMaster && cpuAmount > 1) {
		for (let i = 0; i < cpuAmount; i++) {
			cluster.fork(process.env);
		}

		cluster.on("fork", (worker) => {
			logger.info(`${pkg.name} - subprocess(${worker.process.pid}) starting...`);
			worker.timestamp = Date.now();
		});

		cluster.on("exit", (worker, code, signal) => {
			logger.log({level: "info", message: `${pkg.name} - subprocess(${worker.process.pid}) exited with code ${code}`});
			if (code !== 0 && Date.now() - worker.timestamp < 2000) {
				logger.log({level: "info", message: `${pkg.name} - subprocess(${worker.process.pid}) exited too soon and will try to respawn after a minute`});
				setTimeout(() => {
					cluster.fork();
				}, 60000);
			}
			else {
				cluster.fork();
			}
		});
	}
	else {
		await startServer(argv);
	}
}


init();



function fileExists (path) {
	try {
		if (fs.existsSync(path)) {
			return true;
		}
	}
	catch (err) {
		console.error(err);
	}
	return false;
}

function getPackageDir (dir = __dirname) {
	let p = "./";
	let ex;
	while (!(ex = fileExists(path.resolve(dir, p, "package.json")), ex) && path.resolve(dir, p) !== path.resolve("/")) {
		p = p === "./" ? "../" : `${p}../`;
	}
	if (ex) {
		return path.resolve(dir, p);
	}
}

function getJSON (uri) {
	try {
		return JSON.parse(fs.readFileSync(path.resolve(packageDir, uri), "utf8"));
	}
	catch (error) {
		return {};
	}
}

async function runWorker (workerData) {
	return new Promise((resolve, reject) => {
		const worker = new Worker("./worker.mjs", {workerData});
		worker.on("message", resolve);
		worker.on("error", reject);
		worker.on("exit", (code) => {
			if (code !== 0) {
				reject(new Error(`Worker stopped with exit code ${code}`));
			}
		});
	});
}
