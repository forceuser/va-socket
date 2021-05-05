import winston from "winston";

const {createLogger, format, transports} = winston;
const logger = createLogger({
	// format: format.json(),
	exitOnError: false,
	defaultMeta: {},
	format: format.combine(
		format.errors({stack: true}),
		// format.metadata(),
	),
	level: "info",
	transports: [],
});

export default logger;
