// ==================== 工具函数 ====================
function stringToArray(str) {
  if (typeof str !== 'string') return [];
  return str.split(';').map(item => item.trim()).filter(item => item.length > 0);
}

function safeRegexTest(regex, str) {
  try {
    return regex.test(str);
  } catch (e) {
    console.warn('正则匹配失败:', e.message);
    return false;
  }
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
  ipv6: false,
  logLevel: 'warning',
  tunMTU: 1500,
  dnsListen: '127.0.0.1:1053',
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
  tunMTU = 1500,
  dnsListen = '127.0.0.1:1053',
} = args;

if (typeof globalRatioLimit !== 'number' || globalRatioLimit < 0.1 || globalRatioLimit > 100) {
  console.warn('globalRatioLimit 参数异常，使用默认值 2');
  globalRatioLimit = 2;
}

const dnsPresets = {
  securest: {
    // ... 其他保持不变
    // 建议把这里也改了
    foreignDNS: ['https://8.8.8.8/dns-query', 'https://1.1.1.1/dns-query'],
  },
  secure: {
    // ... 其他保持不变
    // 【修改点 1】给 secure 模式也打上补丁
    foreignDNS: ['https://8.8.8.8/dns-query', 'https://1.1.1.1/dns-query'],
  },
  fast: {
     // ... 保持不变
  },
  fastest: {
    // 您之前已经改好这里了，很好
    defaultDNS: ['119.29.29.29', '223.5.5.5'],
    directDNS: ['119.29.29.29', '223.5.5.5'],
    chinaDNS: ['119.29.29.29', '223.5.5.5'],
    foreignDNS: ['https://8.8.8.8/dns-query', 'https://1.1.1.1/dns-query'],
  },
  default: {
    defaultDNS: ['119.29.29.29', '223.5.5.5'],
    directDNS: ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
    chinaDNS: ['https://doh.pub/dns-query', 'https://223.5.5.5/dns-query'],
    // 【修改点 2 - 关键！】把 default 模式也改成 IP，彻底解决问题
    foreignDNS: ['https://8.8.8.8/dns-query', 'https://1.1.1.1/dns-query'],
  },
};

if (dnsPresets[mode]) {
  ({ defaultDNS, directDNS, chinaDNS, foreignDNS } = dnsPresets[mode]);
} else {
  console.warn(`DNS 模式 "${mode}" 不存在，使用 default 模式`);
  ({ defaultDNS, directDNS, chinaDNS, foreignDNS } = dnsPresets.default);
}

if (typeof skipIps === 'string') skipIps = stringToArray(skipIps);
if (typeof defaultDNS === 'string') defaultDNS = stringToArray(defaultDNS);
if (typeof directDNS === 'string') directDNS = stringToArray(directDNS);
if (typeof chinaDNS === 'string') chinaDNS = stringToArray(chinaDNS);
if (typeof foreignDNS === 'string') foreignDNS = stringToArray(foreignDNS);

// ==================== 2. 节点过滤规则 ====================
const invalidNodeRegex = /^(断线|删除|订阅|重新|导入|全局|模式|防失联|邮箱|客服|官网|群|邀请|返利|循环|网站|网址|获取|流量|到期|机场|下次|版本|官址|备用|过期|已用|联系|工单|贩卖|通知|倒卖|防止|地址|频道|无法|说明|提示|特别|访问|支持|教程|关注|更新|作者|加入|卸载|可解决|只看|USE|USED|TOTAL|EXPIRE|EMAIL|Panel|Channel|Author|traffic)/i;

const selfBuiltRegex = /DIY|自建|VPS|MyNode|Self|NAT/i;

const multiplierRegex = /(?:^|[^\d])([0-9]+(?:\.[0-9]+)?)\s*[xX✕✖⨉倍率]|[xX✕✖⨉倍率]\s*([0-9]+(?:\.[0-9]+)?)(?:[^\d]|$)/;

function extractMultiplier(nodeName) {
  try {
    const match = multiplierRegex.exec(nodeName);
    if (!match) return 1.0;
    
    const ratioStr = match[1] || match[2];
    if (!ratioStr) return 1.0;
    
    const ratio = parseFloat(ratioStr);
    
    if (Number.isNaN(ratio) || ratio < 0.1 || ratio > 100) {
      return 1.0;
    }
    
    return ratio;
  } catch (e) {
    console.warn('倍率提取失败:', nodeName, e.message);
    return 1.0;
  }
}

// ==================== 3. Filter 生成函数 ====================
const invalidFilterWords = '(断线|删除|订阅|重新|导入|全局|模式|防失联|邮箱|客服|官网|群|邀请|返利|循环|网站|网址|获取|流量|到期|机场|下次|版本|官址|备用|过期|已用|联系|工单|贩卖|通知|倒卖|防止|地址|频道|无法|说明|提示|特别|访问|支持|教程|关注|更新|作者|加入|卸载|可解决|只看|USE|USED|TOTAL|EXPIRE|EMAIL|Panel|Channel|Author|traffic)';

function buildFilter(extraPattern) {
  return `(?i)^(?!.*${invalidFilterWords}).*${extraPattern}.*$`;
}

function buildValidOnlyFilter() {
  return `(?i)^(?!.*${invalidFilterWords}).*$`;
}

function buildExcludeFilter(excludePattern) {
  return `(?i)^(?!.*${invalidFilterWords})(?!.*${excludePattern}).*$`;
}

// ==================== 4. 地区定义（【修改点2】已移除韩国节点）====================
const regionDefinitions = [
  {
    name: '香港节点',
    code: 'HK',
    regex: /(香港|Hong\s*Kong|HongKong|\bHK\b)/i,
    filter: '(香港|Hong\\s*Kong|HongKong|\\bHK\\b)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/HongKong.png',
  },
  {
    name: '狮城节点',
    code: 'SG',
    regex: /(新加坡|狮城|獅城|Singapore|\bSG\b)/i,
    filter: '(新加坡|狮城|獅城|Singapore|\\bSG\\b)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Singapore.png',
  },
  {
    name: '日本节点',
    code: 'JP',
    regex: /(日本|Japan|\bJP\b)/i,
    filter: '(日本|Japan|\\bJP\\b)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Japan.png',
  },
  {
    name: '台湾节点',
    code: 'TW',
    regex: /(台湾|台灣|Taiwan|\bTW\b)/i,
    filter: '(台湾|台灣|Taiwan|\\bTW\\b)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/Taiwan.png',
  },
  {
    name: '美国节点',
    code: 'US',
    regex: /(美国|美國|United\s*States|UnitedStates|USA|\bUS\b)/i,
    filter: '(美国|美國|United\\s*States|UnitedStates|USA|\\bUS\\b)',
    icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/UnitedStates.png',
  },
];

const aigcRegionFilter = '(美国|美國|United\\s*States|UnitedStates|USA|\\bUS\\b|台湾|台灣|Taiwan|\\bTW\\b|日本|Japan|\\bJP\\b)';

// ==================== 5. 通用配置 ====================
const ruleProviderCommon = {
  type: 'http',
  interval: 259200,
  proxy: 'DIRECT',
};

const groupBaseOption = {
  interval: 300,
  timeout: 5000,
  url: 'https://www.gstatic.com/generate_204',
  lazy: true,
  'max-failed-times': 3,
  hidden: false,
};

const urlTestOption = {
  ...groupBaseOption,
  interval: 600,
  tolerance: 50,
};

// ==================== 6. 规则提供者定义（【修改点3】移除 direct_domain）====================
const ruleProviderDefinitions = {
  binance_domain: {
    url: 'https://raw.githubusercontent.com/LUCK777777/clash-rule/refs/heads/main/rule/binance.list',
    format: 'text',
    behavior: 'classical',
  },
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
  'ai!cn_domain': {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-!cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  openai_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  ai_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ai-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
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
  microsoft_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  github_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  apple_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  apple_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
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
  twitter_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitter.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  twitter_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/twitter.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
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
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/disney.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  spotify_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  tiktok_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  twitch_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/twitch.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  bahamut_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bahamut.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  paypal_domain: {
    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/PayPal/PayPal.yaml',
    format: 'yaml',
    behavior: 'classical',
  },
  wechat_domain: {
    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/WeChat/WeChat.yaml',
    format: 'yaml',
    behavior: 'classical',
  },
  discord_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  'media!cn_domain': {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-social-media-!cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  bilibili_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/bilibili.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  steam_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  steam_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam@cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  game_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-games@cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  bank_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  alibaba_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/alibaba.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  xiaomi_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/xiaomi.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
  media_cn_domain: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-media-cn.mrs',
    format: 'mrs',
    behavior: 'domain',
  },
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
  cn_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
  private_ip: {
    url: 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/private.mrs',
    format: 'mrs',
    behavior: 'ipcidr',
  },
};

// ==================== 7. 主函数 ====================
function main(config) {
  try {
    if (!enable) return config;

    if (!config.proxies) config.proxies = [];
    if (!config['proxy-providers']) config['proxy-providers'] = {};

    const proxies = config.proxies || [];
    const proxyCount = proxies.length;
    const proxyProviderCount = Object.keys(config['proxy-providers']).length;

    if (proxyCount === 0 && proxyProviderCount === 0) {
      throw new Error('配置文件中未找到任何代理');
    }

    // ==================== 7.1 基础配置 ====================
    Object.assign(config, {
      'mode': 'rule',
      'mixed-port': 7890,
      'ipv6': ipv6,
      'allow-lan': false,
      'unified-delay': true,
      'tcp-concurrent': true,
      'global-ua': 'clash.meta',
      'find-process-mode': 'strict',
      'global-client-fingerprint': 'chrome',
      'log-level': logLevel,
      'keep-alive-idle': 600,
      'keep-alive-interval': 30,
      'geodata-mode': false,
      'geodata-loader': 'memconservative',
      'geo-auto-update': true,
      'geo-update-interval': 168,
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

    // ==================== 7.2 Sniffer 配置 ====================
    config['sniffer'] = {
      enable: true,
      'force-dns-mapping': true,
      'parse-pure-ip': true,
      sniff: {
        HTTP: { ports: [80, '8080-8880'], 'override-destination': true },
        TLS: { ports: [443, 8443] },
        QUIC: { ports: [443, 8443] },
      },
      'skip-domain': [
        '+.push.apple.com',
        '+.apple.com',
        '+.wechat.com',
        '+.qq.com',
        '+.tencent.com',
        '+.vivox.com',
      ],
    };

    // ==================== 7.3 TUN 配置（加强防泄露）====================
    config['tun'] = {
      enable: true,
      stack: 'mixed',
      mtu: tunMTU,
      'dns-hijack': ['any:53', 'tcp://any:53'],
      'auto-route': true,
      'auto-redirect': true,
      'auto-detect-interface': true,
      'strict-route': true,
      'endpoint-independent-nat': true,
    };

    // ==================== 7.4 DNS 配置（IPv6支持 & Fake-IP增强）====================
    const dnsNameservers = [...foreignDNS];
    const dnsDefaultNameserver = [...defaultDNS];
    
    if (ipv6) {
      dnsNameservers.push('2001:4860:4860::8888', '2606:4700:4700::1111');
      dnsDefaultNameserver.push('2400:3200::1', '2400:3200:baba::1');
    }

    config['dns'] = {
      enable: true,
      listen: dnsListen,
      ipv6: ipv6,
      'prefer-h3': true,
      'use-hosts': true,
      'use-system-hosts': false,
      'respect-rules': true,
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'fake-ip-filter-mode': 'blacklist',
      'fake-ip-filter': [
        // 【修改点4】增强 Fake-IP 过滤，防止国产应用异常
        '*.lan',
        '*.local',
        '*.localhost',
        'time.*.com',
        'ntp.*.com',
        '+.pool.ntp.org',
        '+.msftconnecttest.com',
        '+.msftncsi.com',
        'geosite:cn',
        'geosite:private',
        '+.stun.*.*',
        '+.stun.*',
        '+.wechat.com',
        '+.kg.qq.com',
        '+.wanggou.com',
        '+.jd.com',
        '+.mi.com',
        'mesh.ts.net',
      ],
      'default-nameserver': dnsDefaultNameserver,
      'proxy-server-nameserver': chinaDNS,
      'direct-nameserver': directDNS,
      'direct-nameserver-follow-policy': true,
      'nameserver': dnsNameservers,
      'cache-algorithm': 'arc',
      'nameserver-policy': {
        'rule-set:cn_domain': chinaDNS,
        'rule-set:private_domain': directDNS,
        'rule-set:gfw_domain': foreignDNS,
        'rule-set:geolocation-!cn': foreignDNS,
        'geosite:cn': chinaDNS,
        'geosite:private': directDNS,
      },
    };

    // ==================== 7.5 代理分类 ====================
    const hasProxyProviders = proxyProviderCount > 0;

    const regionGroups = {};
    regionDefinitions.forEach(r => {
      regionGroups[r.name] = { ...r, proxies: [] };
    });

    if (!hasProxyProviders) {
      for (let i = 0; i < proxyCount; i++) {
        try {
          const proxy = proxies[i];
          const name = proxy.name;
          
          if (!name || typeof name !== 'string') continue;
          if (safeRegexTest(invalidNodeRegex, name)) continue;

          if (excludeHighPercentage) {
            const ratio = extractMultiplier(name);
            if (ratio > globalRatioLimit) continue;
          }

          for (const region of regionDefinitions) {
            if (safeRegexTest(region.regex, name)) {
              regionGroups[region.name].proxies.push(name);
              break;
            }
          }
        } catch (e) {
          console.warn('节点处理失败:', i, e.message);
          continue;
        }
      }
    }

    // ==================== 7.6 生成地区策略组 ====================
    const generatedRegionGroups = [];

    regionDefinitions.forEach(r => {
      try {
        const groupData = regionGroups[r.name];

        if (hasProxyProviders) {
          generatedRegionGroups.push({
            ...urlTestOption,
            name: r.name,
            type: 'url-test',
            icon: r.icon,
            'include-all': true,
            filter: buildFilter(r.filter),
          });
        } else if (groupData.proxies.length > 0) {
          generatedRegionGroups.push({
            ...urlTestOption,
            name: r.name,
            type: 'url-test',
            icon: r.icon,
            proxies: groupData.proxies,
          });
        } else {
          generatedRegionGroups.push({
            ...urlTestOption,
            name: r.name,
            type: 'select',
            icon: r.icon,
            proxies: ['DIRECT'],
          });
        }
      } catch (e) {
        console.error('策略组生成失败:', r.name, e.message);
        generatedRegionGroups.push({
          name: r.name,
          type: 'select',
          proxies: ['DIRECT'],
        });
      }
    });

    const regionGroupNames = generatedRegionGroups.map(g => g.name);

    // ==================== 7.7 构建策略组 ====================
    const proxyGroups = [];

    proxyGroups.push({
      ...groupBaseOption,
      name: '故障转移',
      type: 'fallback',
      'include-all': true,
      filter: buildValidOnlyFilter(),
      hidden: true,
      icon: 'https://pub-8feead0908f649a8b94397f152fb9cba.r2.dev/fallback.png',
    });

    proxyGroups.push({
      ...groupBaseOption,
      name: '全部节点',
      type: 'select',
      'include-all': true,
      filter: buildValidOnlyFilter(),
      icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-yu-96.png',
    });

    proxyGroups.push({
      ...groupBaseOption,
      name: '自建节点',
      type: 'select',
      'include-all': true,
      filter: buildFilter('(DIY|自建|VPS|MyNode|Self|NAT)'),
      icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-cloudflare-96.png',
    });

    proxyGroups.push(...generatedRegionGroups);

    const otherExclude = `(DIY|自建|VPS|MyNode|Self|NAT|${regionDefinitions.map(r => r.filter).join('|')})`;
    proxyGroups.push({
      ...groupBaseOption,
      name: '其他节点',
      type: 'select',
      'include-all': true,
      filter: buildExcludeFilter(otherExclude),
      icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/WorldMap.png',
    });

    const selectProxies = ['自建节点', ...regionGroupNames, '其他节点', 'DIRECT'];
    
    // 【修改点5】服务策略组的候选列表，移除了 "自选策略"
    const serviceProxies = ['自建节点', ...regionGroupNames, '其他节点', 'DIRECT'];

    proxyGroups.push({
      ...groupBaseOption,
      name: '自选策略',
      type: 'select',
      proxies: selectProxies,
      icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-zy-100.png',
    });

    // 【修改点6】AIGC 策略组：使用 aigcRegionFilter (美/日/台) 进行过滤
    proxyGroups.push({
      ...groupBaseOption,
      name: 'AIGC',
      type: 'select',
      'include-all': true,
      filter: buildFilter(aigcRegionFilter), // 只保留美国/日本/台湾
      icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/ChatGPT.png',
    });

    const otherServiceGroups = [
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

    otherServiceGroups.forEach(({ name, icon }) => {
      proxyGroups.push({
        ...groupBaseOption,
        name,
        type: 'select',
        proxies: serviceProxies, // 不再包含“自选策略”
        icon,
      });
    });

    proxyGroups.push({
      ...groupBaseOption,
      name: 'WeChat',
      type: 'select',
      proxies: ['DIRECT', ...regionGroupNames],
      icon: 'https://raw.githubusercontent.com/jnlaoshu/MySelf/main/image/WeChat.png',
    });

    proxyGroups.push({
      ...groupBaseOption,
      name: 'TRDR',
      type: 'select',
      'include-all': true,
      filter: buildValidOnlyFilter(),
      icon: 'https://raw.githubusercontent.com/LUCK777777/photo/main/icons8-usdt144.png',
    });

    config['proxy-groups'] = proxyGroups;

    // ==================== 7.8 规则提供者 ====================
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

    // ==================== 7.9 规则 ====================
    config['rules'] = [
      'DOMAIN-SUFFIX,trdr.io,TRDR',
      'DOMAIN-SUFFIX,perplexity.ai,AIGC',
      'DOMAIN-SUFFIX,pplx.ai,AIGC',
      'RULE-SET,binance_domain,交易所',
      'RULE-SET,github_domain,GitHub',
      'RULE-SET,openai_domain,AIGC',
      'RULE-SET,ai!cn_domain,AIGC',
      'RULE-SET,private_domain,DIRECT',
      'RULE-SET,private_ip,DIRECT,no-resolve',
      'RULE-SET,cn_ip,DIRECT,no-resolve',
      'RULE-SET,wechat_domain,WeChat',
      'RULE-SET,apple_cn_domain,DIRECT',
      'RULE-SET,ai_cn_domain,DIRECT',
      'RULE-SET,alibaba_domain,DIRECT',
      'RULE-SET,xiaomi_domain,DIRECT',
      'RULE-SET,bilibili_domain,DIRECT',
      'RULE-SET,bank_cn_domain,DIRECT',
      'RULE-SET,game_cn_domain,DIRECT',
      'RULE-SET,media_cn_domain,DIRECT',
      'RULE-SET,steam_cn_domain,DIRECT',
      'RULE-SET,cn_domain,DIRECT', // 【修改点7】用 cn_domain 替换了 direct_domain
      'RULE-SET,twitter_domain,Twitter',
      'RULE-SET,twitter_ip,Twitter,no-resolve',
      'RULE-SET,youtube_domain,YouTube',
      'RULE-SET,google_domain,Google',
      'RULE-SET,google_ip,Google,no-resolve',
      'RULE-SET,telegram_domain,Telegram',
      'RULE-SET,telegram_ip,Telegram,no-resolve',
      'RULE-SET,netflix_domain,Netflix',
      'RULE-SET,netflix_ip,Netflix,no-resolve',
      'RULE-SET,disney_domain,Disney',
      'RULE-SET,spotify_domain,Spotify',
      'RULE-SET,tiktok_domain,TikTok',
      'RULE-SET,twitch_domain,自选策略',
      'RULE-SET,bahamut_domain,台湾节点',
      'RULE-SET,microsoft_domain,Microsoft',
      'RULE-SET,apple_domain,Apple',
      'RULE-SET,paypal_domain,PayPal',
      'RULE-SET,discord_domain,自选策略',
      'RULE-SET,steam_domain,自选策略',
      'RULE-SET,media!cn_domain,自选策略',
      'RULE-SET,gfw_domain,自选策略',
      'RULE-SET,geolocation-!cn,自选策略',
      'RULE-SET,cn_domain,DIRECT',
      'MATCH,自选策略',
    ];

    // ==================== 7.10 配置统计 ====================
    if (logLevel === 'info' || logLevel === 'debug') {
      console.log('='.repeat(50));
      console.log('📊 Clash 配置统计');
      console.log('='.repeat(50));
      console.log(`代理节点数: ${proxyCount}`);
      console.log(`订阅源数: ${proxyProviderCount}`);
      console.log(`策略组数: ${proxyGroups.length}`);
      console.log(`规则数: ${config['rules'].length}`);
      console.log(`规则提供者: ${Object.keys(ruleProviders).length}`);
      console.log(`IPv6支持: ${ipv6 ? '已启用' : '未启用'}`);
      console.log(`TUN模式: ${config['tun'].stack}`);
      console.log('='.repeat(50));
    }

    return config;

  } catch (error) {
    console.error('脚本执行失败:', error.message);
    console.error('堆栈:', error.stack);
    console.warn('降级：返回原始配置');
    return config;
  }
}
