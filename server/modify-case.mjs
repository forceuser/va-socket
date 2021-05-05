export default function (key, settings, delimiter = "", breakByCase = false) {
	if (typeof settings === "string") {
		settings = {format: settings};
	}
	settings = Object.assign({
		splitBy: /[-_]|\s/,
		delimiter,
		keepCase: false,
		breakByCase,
	}, settings);

	const matchFormat = f => (settings.format || "").startsWith(f);

	if (["kebab", "lisp"].some(matchFormat)) {
		settings.format = "lower";
		settings.delimiter = "-";
	}
	else if (["snake"].some(matchFormat)) {
		settings.format = "lower";
		settings.delimiter = "_";
	}
	else if (["const"].some(matchFormat)) {
		settings.format = "upper";
		settings.delimiter = "_";
	}


	if (!["lower", "upper", "camel", "pascal", "capital", "title", "abbr", "normal"].some(matchFormat)) {
		return key;
	}

	const multiCase = key !== key.toUpperCase() && key !== key.toLowerCase();

	let parts = [];
	if (settings.delimiter === false || settings.splitBy === false) {
		settings.delimiter = "";
		parts = [key];
	}
	else {
		if (settings.breakByCase && multiCase) {
			let prev;
			for (const char of key) {
				if (char.match(settings.splitBy)) {
					parts[parts.length] = "";
				}
				else if (prev && (prev + char).match(/\p{Ll}\p{Lu}/u)) {
					parts[parts.length] = char;
				}
				else {
					const idx = parts.length - 1 > 0 ? parts.length - 1 : 0;
					parts[idx] = (parts[idx] || "") + char;
				}
				prev = char;
			}
		}
		else {
			parts = key.split(settings.splitBy);
		}
		parts = parts.filter(part => part);
	}

	return parts
		.map((part, idx) => {
			if (settings.format.startsWith("lower")) {
				return part.toLowerCase();
			}
			else if (settings.format.startsWith("upper")) {
				return part.toUpperCase();
			}
			else if (settings.format.startsWith("camel")) {
				return idx > 0 ? part.substr(0, 1).toUpperCase() + (settings.keepCase ? (part.substr(1) || "") : (part.substr(1) || "").toLowerCase()) : part.toLowerCase();
			}
			else if (settings.format.startsWith("pascal")) {
				return part.substr(0, 1).toUpperCase() + (settings.keepCase ? (part.substr(1) || "") : (part.substr(1) || "").toLowerCase());
			}
			else if (settings.format.startsWith("capital")) {
				return part.substr(0, 1).toUpperCase() + part.substr(1);
			}
			else if (settings.format.startsWith("title")) {
				return idx > 0 ? (settings.keepCase ? part : part.toLowerCase()) : (part.substr(0, 1).toUpperCase() + (settings.keepCase ? (part.substr(1) || "") : (part.substr(1) || "").toLowerCase()));
			}
			else if (settings.format.startsWith("abbr")) {
				return part.toUpperCase() === part ? part : part.substr(0, 1).toUpperCase();
			}

			return part;
		})
		.join(settings.delimiter || "");
}
