function add0x(input) {
  if (typeof input !== "string") {
    return input;
  }
  if (input.length < 2 || input.slice(0, 2) !== "0x") {
    return "0x" + input;
  }

  return input;
}

function strip0x(input) {
  if (typeof input !== "string") {
    return input;
  } else if (input.length >= 2 && input.slice(0, 2) === "0x") {
    return input.slice(2);
  } else {
    return input;
  }
}

module.exports = { add0x, strip0x };
