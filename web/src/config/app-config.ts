import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "P3Y",
  displayVersion: "v0.91",
  version: packageJson.version,
  copyright: `© ${currentYear}, P3Y.`,
  meta: {
    title: "P3Y智能攻防系统控制台",
    description: "LLM 驱动的 CTF 解题与自主网络攻防系统控制台",
  },
};
