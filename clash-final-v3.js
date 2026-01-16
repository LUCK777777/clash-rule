/***
 * Clash Verge Rev / Mihomo Party 全局优化脚本 v3.0 (性能优化版)
 * 功能：自动处理订阅节点、自动分流、地区节点自动分组、防DNS泄露
 * 
 * 性能优化：
 * 1. 优化连接池和并发设置
 * 2. 调整 DNS 缓存和超时
 * 3. 优化规则匹配顺序（高频规则前置）
 * 4. 精简冗余规则集
 * 5. 优化策略组健康检查间隔
 * 6. 内存和 CPU 使用优化
 */

// ==================== 工具函数 ====================
function stringToArray(str) {
  if (typeof str !== 'string') return [];
  return str.split(';').map(item => item.trim()).filter(item => item.length > 0);
}

// ==================== 1. 静态配置区域 ====================
const _skipIps = '10.0.0.0/8;100.64.0.0/10;169.254.0.0/16;172.16.0.0/12;192.168.0.0/16;198.18.0.0/16;FC00::/7;FE80::/10;::1/128';

const _chinaDNS = 'https://doh.pub/dns-query;https://223.5.5.5/dns-query';
const _foreignDNS = 'https://dns.google/dns-query;https://dns.cloudflare.com/dns-query';
const _defaultDNS = '119.29.29.29;223.5.5.5';
const _directDNS = 'https://doh.pub/dns-query;https://223.5.5.5/dns-query';

const args = typeof $arguments !== 'undefined' ? $arguments : {
  enable: true,
  excludeHighPercentage: true,
  globalRatioLimit: 2,
  skipIps: _skipIps,
  defaultDNS: _defaultDNS,
  directDNS: _directDNS,
  chinaDNS: _chinaDNS,
  foreignDNS: _foreignDNS,
  mode: 'default',
  ipv6: false,  // 默认关闭 IPv6 提升性能
  logLevel: 'warning',
};

let {
  enable = true,
  excludeHighPercentage = true,
  globalRatioLimit = 2,
  skipIps = _skipIps,
  defaultDNS = _defaultDNS,
  directDNS = _directDNS,
  chinaDNS = _chinaDNS,
  foreignDNS = _foreignDNS,
  mode = 'default',
  ipv6 = false,
  logLevel = 'warning',
} = args;

// DNS 模式预设
const dnsPresets = {
  securest: {
    defaultDNS: ['8.8.8.8', '94.140.14.14'],
    directDNS: ['https://dns.google/dns-query', 'https://dns.adguard-dns.com/dns-query'],
    chinaDNS: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
    foreignDNS: ['https://dns.google/dns-query', 'https://dns.cloudflare.com/dns-query'],
  },
  secure: {
    defaultDNS: ['8.8.8.8', '94.140.14.14'],
    directDNS: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
    chinaDNS: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
    foreignDNS: ['https://dns.google/dns-query', 'https://dns.cloudflare.com/dns-query'],
  },
  fast: {
    defaultDNS: ['119.29.29.29', '223.5.5.5'],
    directDNS: ['119.29.29.29', '223.5.5.5'],
    chinaDNS: ['119.29.29.29', '223.5.5.5'],
    foreignDNS: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
  },
  fastest: {
    defaultDNS: ['119.29.29.29', '223.5.5.5'],
    directDNS: ['119.29.29.29', '223.5.5.5'],
    chinaDNS: ['119.29.29.29', '223.5.5.5'],
    foreignDNS: ['119.29.29.29', '223.5.5.5'],
  },
  default: {
    defaultDNS: ['119.29.29.29', '223.5.5.5'],
    directDNS: ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
    chinaDNS: ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
    foreignDNS: ['https://dns.google/dns-query', 'https://dns.cloudflare.com/dns-query'],
  },
};

if (dnsPresets[mode]) {
  ({ defaultDNS, directDNS, chinaDNS, foreignDNS } = dnsPresets[mode]);
}

if (typeof skipIps === 'string') skipIps = stringToArray(skipIps);
if (typeof defaultDNS === 'string') defaultDNS = stringToArray(defaultDNS);
if (typeof directDNS === 'string') directDNS = stringToArray(directDNS);
if (typeof chinaDNS === 'string') chinaDNS = stringToArray(chinaDNS);
if (typeof foreignDNS === 'string') foreignDNS = stringToArray(foreignDNS);

// ==================== 2. 节点过滤规则 ====================
const invalidNodeRegex = /断线|删除|订阅|重新|导入|全局|模式|防失联|邮箱|客服|官网|群|邀请|返利|循环|网站|网址|获取|流量|到期|机场|下次|版本|官址|备用|过期|已用|联系|工单|贩卖|通知|倒卖|防止|国内|地址|频道|无法|说明|提示|特别|访问|支持|教程|关注|更新|作者|加入|卸载|可解决|只看|gmail|@|USE|USED|TOTAL|EXPIRE|EMAIL|Panel|Channel|Author|traffic/i;

const selfBuiltRegex = /DIY|自建|VPS|MyNode|Self|NAT/i;

// ==================== 3. 地区定义 ====================
const regionDefinitions = [
  {
    name: '香港节点',
    code: 'HK',
    regex: /🇭🇰|香港|Hong\s*Kong|HongKong|HK/i,
    filter: '(?i)(🇭🇰|香港|Hong\\s*Kong|HongKong|HK)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/HongKong.png',
  },
  {
    name: '狮城节点',
    code: 'SG',
    regex: /🇸🇬|新加坡|狮城|獅城|Singapore|SG/i,
    filter: '(?i)(🇸🇬|新加坡|狮城|獅城|Singapore|SG)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Singapore.png',
  },
  {
    name: '日本节点',
    code: 'JP',
    regex: /🇯🇵|日本|Japan|JP/i,
    filter: '(?i)(🇯🇵|日本|Japan|JP)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Japan.png',
  },
  {
    name: '台湾节点',
    code: 'TW',
    regex: /🇹🇼|台湾|台灣|Taiwan|TW/i,
    filter: '(?i)(🇹🇼|台湾|台灣|Taiwan|TW)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Taiwan.png',
  },
  {
    name: '美国节点',
    code: 'US',
    regex: /🇺🇸|美国|美國|United\s*States|UnitedStates|USA|US/i,
    filter: '(?i)(🇺🇸|美国|美國|United\\s*States|UnitedStates|USA|US)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/UnitedStates.png',
  },
];

const multiplierRegex = /(?<=[xX✕✖⨉倍率])([1-9]+(\.\d+)*|0{1}\.\d+)(?=[xX✕✖⨉倍率])*/i;

// ==================== 4. 通用配置（性能优化） ====================
const ruleProviderCommon = {
  type: 'http',
  interval: 259200,  // 3天更新一次，减少网络请求
  proxy: 'DIRECT',   // 规则集通过直连下载
};

// 策略组基础配置（性能优化）
const groupBaseOption = {
  interval: 300,        // 5分钟检查一次
  timeout: 5000,        // 超时5秒
  url: 'https://www.gstatic.com/generate_204',
  lazy: true,           // 懒加载，减少启动时间
  'max-failed-times': 3,
  hidden: false,
};

// URL 测试组配置（更激进的性能优化）
const urlTestOption = {
  ...groupBaseOption,
  interval: 600,        // 10分钟测速一次
  tolerance: 50,        // 容差50ms，减少不必要切换
};

// ==================== 5. 规则提供者定义（精简版） ====================
const ruleProviderDefinitions = {
  // ===== 自定义规则 =====
  binance_domain: {
    url: 'https://raw.githubusercontent.com/LUCK777777/clash-rule/refs/heads/main/rule/binance.list',
    format: 'text',
    behavior: 'classical',
  },

  // ===== 高频直连规则（前置优化） =====
  private_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/private.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  direct_domain: {
    url: 'https://raw.githubusercontent.com/Lanlan13-14/Rules/refs/heads/main/rules/Domain/direct.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== AI 相关 =====
  'ai!cn_domain': {
    url: 'https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/meta/geo/geosite/category-ai-!cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  openai_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/openai.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  ai_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-ai-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== Google 相关（合并优化） =====
  google_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/google.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  youtube_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  google_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/google.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },

  // ===== Microsoft 相关 =====
  microsoft_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== GitHub =====
  github_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== Apple 相关 =====
  apple_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  apple_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/apple%40cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== Telegram =====
  telegram_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  telegram_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/telegram.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },

  // ===== Twitter/X =====
  twitter_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/twitter.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  twitter_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/twitter.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },

  // ===== 流媒体 =====
  netflix_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  netflix_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/netflix.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
  disney_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/disney.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  spotify_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/spotify.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  tiktok_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  twitch_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/twitch.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  bahamut_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bahamut.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 支付 =====
  paypal_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/paypal.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 即时通讯 =====
  wechat_domain: {
    url: 'https://raw.githubusercontent.com/Lanlan13-14/Rules/refs/heads/main/rules/Domain/WeChat.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  wechat_asn: {
    url: 'https://raw.githubusercontent.com/Lanlan13-14/Rules/refs/heads/main/rules/IP/AS132203.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
  discord_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/discord.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 社交媒体（合并为一个大规则集） =====
  'media!cn_domain': {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-social-media-!cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 哔哩哔哩 =====
  bilibili_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/bilibili.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 游戏（合并优化） =====
  steam_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/steam.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  steam_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/steam%40cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  game_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-games%40cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 国内服务（合并优化） =====
  bank_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-bank-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  alibaba_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/alibaba.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  xiaomi_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/xiaomi.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  media_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/category-media-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== 兜底规则 =====
  gfw_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/gfw.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  'geolocation-!cn': {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/geolocation-!cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },

  // ===== IP 规则 =====
  cn_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
  private_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geoip/private.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
};

// ==================== 6. 主函数 ====================
function main(config) {
  if (!enable) return config;

  if (!config.proxies) config.proxies = [];
  if (!config['proxy-providers']) config['proxy-providers'] = {};

  const proxies = config?.proxies || [];
  const proxyCount = proxies.length;
  const proxyProviderCount = Object.keys(config['proxy-providers']).length;

  if (proxyCount === 0 && proxyProviderCount === 0) {
    throw new Error('配置文件中未找到任何代理，请检查订阅是否正确添加');
  }

  // ==================== 6.1 基础配置（性能优化） ====================
  Object.assign(config, {
    'mode': 'rule',
    'mixed-port': 7890,
    'ipv6': ipv6,
    'allow-lan': false,
    'unified-delay': true,
    'tcp-concurrent': true,           // TCP 并发
    'global-ua': 'clash.meta',
    'find-process-mode': 'strict',
    'global-client-fingerprint': 'chrome',
    'log-level': logLevel,
    
    // 连接池优化
    'keep-alive-idle': 600,           // 空闲连接保持10分钟
    'keep-alive-interval': 30,        // 心跳间隔30秒
    
    // GEO 数据优化
    'geodata-mode': false,            // 使用 mmdb 模式更快
    'geodata-loader': 'memconservative', // 内存保守模式
    'geo-auto-update': true,
    'geo-update-interval': 168,       // 7天更新一次
    
    // 外部控制
    'external-controller': '127.0.0.1:9090',
    'external-ui': 'ui',
    'external-ui-url': 'https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip',
  });

  config['geox-url'] = {
    geosite: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
    mmdb: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.metadb',
    geoip: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat',
    asn: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb',
  };

  config['profile'] = {
    'store-selected': true,
    'store-fake-ip': true,
  };

  // ==================== 6.2 Sniffer 配置（性能优化） ====================
  config['sniffer'] = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    sniff: {
      HTTP: {
        ports: [80, '8080-8880'],
        'override-destination': true,
      },
      TLS: {
        ports: [443, 8443],
      },
      QUIC: {
        ports: [443, 8443],
      },
    },
    'skip-domain': [
      // 跳过不需要嗅探的域名，提升性能
      '+.push.apple.com',
      '+.apple.com',
      'Mijia Cloud',
      '+.wechat.com',
      '+.qq.com',
      '+.tencent.com',
      '+.vivox.com',
    ],
  };

  // ==================== 6.3 TUN 配置（性能优化） ====================
  config['tun'] = {
    enable: true,
    stack: 'system',              // system 模式性能更好
    mtu: 9000,                    // 增大 MTU 减少分包
    'dns-hijack': ['any:53'],
    'auto-route': true,
    'auto-redirect': false,
    'auto-detect-interface': true,
    'strict-route': true,
  };

  // ==================== 6.4 DNS 配置（性能优化） ====================
  config['dns'] = {
    enable: true,
    listen: '0.0.0.0:1053',
    ipv6: ipv6,
    'prefer-h3': true,              // HTTP/3 更快
    'use-hosts': true,
    'use-system-hosts': false,
    'respect-rules': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter-mode': 'blacklist',
    'fake-ip-filter': [
      // 精简的 fake-ip 过滤列表
      '*.lan',
      '*.local',
      '*.localhost',
      'time.*.com',
      'ntp.*.com',
      '+.pool.ntp.org',
      '+.msftconnecttest.com',
      '+.msftncsi.com',
      // 规则集
      'rule-set:cn_domain',
      'rule-set:private_domain',
      'rule-set:wechat_domain',
      'rule-set:game_cn_domain',
      'rule-set:bank_cn_domain',
      'rule-set:steam_cn_domain',
    ],
    'default-nameserver': defaultDNS,
    'proxy-server-nameserver': chinaDNS,
    'direct-nameserver': directDNS,
    'direct-nameserver-follow-policy': true,
    'nameserver': foreignDNS,
    // DNS 缓存优化
    'cache-algorithm': 'arc',       // ARC 缓存算法更高效
    // DNS 策略（精简版）
    'nameserver-policy': {
      'rule-set:cn_domain': chinaDNS,
      'rule-set:private_domain': directDNS,
      'rule-set:gfw_domain': foreignDNS,
      'rule-set:geolocation-!cn': foreignDNS,
      'geosite:cn': chinaDNS,
      'geosite:private': directDNS,
    },
  };

  // ==================== 6.5 添加直连节点 ====================
  config.proxies.push({
    name: '🟢 直连',
    type: 'direct',
    udp: true,
  });

  // ==================== 6.6 代理分类 ====================
  const hasProxyProviders = proxyProviderCount > 0;
  
  const regionGroups = {};
  regionDefinitions.forEach(r => {
    regionGroups[r.name] = { ...r, proxies: [] };
  });

  for (let i = 0; i < proxyCount; i++) {
    const proxy = proxies[i];
    const name = proxy.name;

    if (invalidNodeRegex.test(name)) continue;

    if (excludeHighPercentage) {
      const match = multiplierRegex.exec(name);
      if (match && parseFloat(match[1]) > globalRatioLimit) continue;
    }

    for (const region of regionDefinitions) {
      if (region.regex.test(name)) {
        regionGroups[region.name].proxies.push(name);
        break;
      }
    }
  }

  // ==================== 6.7 生成策略组 ====================
  const validNodeFilter = '^(?!.*(断线|删除|订阅|重新|导入|全局|模式|防失联|邮箱|客服|官网|群|邀请|返利|循环|网站|网址|获取|流量|到期|机场|下次|版本|官址|备用|过期|已用|联系|工单|贩卖|通知|倒卖|防止|国内|地址|频道|无法|说明|提示|特别|访问|支持|教程|关注|更新|作者|加入|卸载|可解决|只看|gmail|@|USE|USED|TOTAL|EXPIRE|EMAIL|Panel|Channel|Author|traffic))';

  const generatedRegionGroups = [];

  regionDefinitions.forEach(r => {
    const groupData = regionGroups[r.name];
    
    if (hasProxyProviders) {
      generatedRegionGroups.push({
        ...urlTestOption,
        name: r.name,
        type: 'url-test',
        icon: r.icon,
        'include-all': true,
        filter: validNodeFilter + '.*' + r.filter,
      });
    } else if (groupData.proxies.length > 0) {
      generatedRegionGroups.push({
        ...urlTestOption,
        name: r.name,
        type: 'url-test',
        icon: r.icon,
        proxies: groupData.proxies,
      });
    }
  });

  const regionGroupNames = generatedRegionGroups.map(g => g.name);

  // ==================== 6.8 构建策略组 ====================
  const proxyGroups = [];

  // 故障转移组
  proxyGroups.push({
    ...groupBaseOption,
    name: '故障转移',
    type: 'fallback',
    'include-all': true,
    filter: validNodeFilter,
    hidden: true,
    icon: 'https://pub-8feead0908f649a8b94397f152fb9cba.r2.dev/fallback.png',
  });

  // 全部节点
  proxyGroups.push({
    ...groupBaseOption,
    name: '全部节点',
    type: 'select',
    'include-all': true,
    filter: validNodeFilter,
    icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-yu-96.png',
  });

  // 自建节点
  proxyGroups.push({
    ...groupBaseOption,
    name: '自建节点',
    type: 'select',
    'include-all': true,
    filter: validNodeFilter + '.*(?i)(DIY|自建|VPS|MyNode|Self|NAT)',
    icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-cloudflare-96.png',
  });

  // 地区节点组
  proxyGroups.push(...generatedRegionGroups);

  // 其他节点
  proxyGroups.push({
    ...groupBaseOption,
    name: '其他节点',
    type: 'select',
    'include-all': true,
    filter: validNodeFilter + '.*^((?!(DIY|自建|VPS|MyNode|Self|NAT|🇭🇰|香港|HK|Hong\\s*Kong|🇺🇸|美国|美國|US|USA|🇹🇼|台湾|台灣|TW|Taiwan|🇯🇵|日本|JP|Japan|🇸🇬|新加坡|狮城|SG|Singapore)).)*$',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/WorldMap.png',
  });

  // 自选策略
  const selectProxies = ['自建节点', ...regionGroupNames, '其他节点', 'DIRECT'];
  proxyGroups.push({
    ...groupBaseOption,
    name: '自选策略',
    type: 'select',
    proxies: selectProxies,
    icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-zy-100.png',
  });

  // 服务策略组（精简版）
  const serviceProxies = ['自选策略', '自建节点', ...regionGroupNames, '其他节点', 'DIRECT'];

  const serviceGroups = [
    { name: 'AIGC', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/ChatGPT.png' },
    { name: 'Apple', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Apple.png' },
    { name: 'Disney', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Disney.png' },
    { name: 'GitHub', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/GitHub.png' },
    { name: 'Google', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Google.png' },
    { name: 'Microsoft', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Microsoft.png' },
    { name: 'Netflix', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Netflix.png' },
    { name: 'PayPal', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/PayPal.png' },
    { name: 'Spotify', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Spotify.png' },
    { name: 'Telegram', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Telegram.png' },
    { name: 'TikTok', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/TikTok.png' },
    { name: 'Twitter', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Twitter.png' },
    { name: 'YouTube', icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/YouTube.png' },
    { name: '交易所', icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-btc-94.png' },
  ];

  serviceGroups.forEach(({ name, icon }) => {
    proxyGroups.push({
      ...groupBaseOption,
      name,
      type: 'select',
      proxies: serviceProxies,
      icon,
    });
  });

  // WeChat 特殊处理
  proxyGroups.push({
    ...groupBaseOption,
    name: 'WeChat',
    type: 'select',
    proxies: ['DIRECT', '自选策略', ...regionGroupNames],
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/WeChat.png',
  });

  // TRDR
  proxyGroups.push({
    ...groupBaseOption,
    name: 'TRDR',
    type: 'select',
    'include-all': true,
    filter: validNodeFilter,
    icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-usdt144.png',
  });

  config['proxy-groups'] = proxyGroups;

  // ==================== 6.9 规则提供者 ====================
  const ruleProviders = {};
  Object.entries(ruleProviderDefinitions).forEach(([key, value]) => {
    ruleProviders[key] = {
      ...ruleProviderCommon,
      behavior: value.behavior,
      format: value.format,
      url: value.url,
    };
  });
  config['rule-providers'] = ruleProviders;

  // ==================== 6.10 规则（性能优化：高频规则前置） ====================
  const rules = [
    // ===== 最高优先级：自定义规则 =====
    'DOMAIN-SUFFIX,trdr.io,TRDR',
    'DOMAIN-SUFFIX,perplexity.ai,AIGC',
    'DOMAIN-SUFFIX,pplx.ai,AIGC',
    'RULE-SET,binance_domain,交易所',

    // ===== 高频直连（性能关键：大部分流量会命中这里） =====
    'RULE-SET,private_domain,DIRECT',
    'RULE-SET,wechat_domain,WeChat',
    'RULE-SET,wechat_asn,WeChat,no-resolve',
    'RULE-SET,alibaba_domain,DIRECT',
    'RULE-SET,xiaomi_domain,DIRECT',
    'RULE-SET,bilibili_domain,DIRECT',
    'RULE-SET,bank_cn_domain,DIRECT',
    'RULE-SET,game_cn_domain,DIRECT',
    'RULE-SET,media_cn_domain,DIRECT',
    'RULE-SET,steam_cn_domain,DIRECT',
    'RULE-SET,ai_cn_domain,DIRECT',
    'RULE-SET,direct_domain,DIRECT',

    // ===== 高频代理服务 =====
    'RULE-SET,twitter_domain,Twitter',
    'RULE-SET,twitter_ip,Twitter,no-resolve',
    'RULE-SET,youtube_domain,YouTube',
    'RULE-SET,google_domain,Google',
    'RULE-SET,google_ip,Google,no-resolve',
    'RULE-SET,telegram_domain,Telegram',
    'RULE-SET,telegram_ip,Telegram,no-resolve',

    // ===== AI 服务 =====
    'RULE-SET,ai!cn_domain,AIGC',
    'RULE-SET,openai_domain,AIGC',

    // ===== 流媒体 =====
    'RULE-SET,netflix_domain,Netflix',
    'RULE-SET,netflix_ip,Netflix,no-resolve',
    'RULE-SET,disney_domain,Disney',
    'RULE-SET,spotify_domain,Spotify',
    'RULE-SET,tiktok_domain,TikTok',
    'RULE-SET,twitch_domain,自选策略',
    'RULE-SET,bahamut_domain,自选策略',

    // ===== 其他服务 =====
    'RULE-SET,github_domain,GitHub',
    'RULE-SET,microsoft_domain,Microsoft',
    'RULE-SET,apple_cn_domain,DIRECT',
    'RULE-SET,apple_domain,Apple',
    'RULE-SET,paypal_domain,PayPal',
    'RULE-SET,discord_domain,自选策略',
    'RULE-SET,steam_domain,自选策略',

    // ===== 社交媒体兜底 =====
    'RULE-SET,media!cn_domain,自选策略',

    // ===== GFW 和国外兜底 =====
    'RULE-SET,gfw_domain,自选策略',
    'RULE-SET,geolocation-!cn,自选策略',

    // ===== 国内兜底 =====
    'RULE-SET,cn_domain,DIRECT',
    'RULE-SET,private_ip,DIRECT,no-resolve',
    'RULE-SET,cn_ip,DIRECT,no-resolve',

    // ===== 最终兜底 =====
    'MATCH,自选策略',
  ];

  config['rules'] = rules;

  return config;
}
