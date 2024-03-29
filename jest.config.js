module.exports = {
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".jsx"],
  testMatch: ["**/*.test.js"],
  transform: {
    "^.+\\.js$": "babel-jest",
  },
  globals: {
    "ts-jest": {
      useESM: true,
    },
  },
  moduleNameMapper: {
    "\\.(css|less|scss)$": "identity-obj-proxy",
  },
  moduleDirectories: ["node_modules", "src"],
};
