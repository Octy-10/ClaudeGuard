/* 离线矢量国旗图标（解决 Windows WebView2 不渲染彩色国旗 Emoji 的问题） */
(() => {
  "use strict";

  const svg = (body) =>
    `<svg class="flag-svg" viewBox="0 0 24 16" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">${body}</svg>`;

  const hStripes = (colors) => {
    const h = 16 / colors.length;
    return svg(
      colors.map((c, i) => `<rect y="${(i * h).toFixed(2)}" width="24" height="${(h + 0.1).toFixed(2)}" fill="${c}"/>`).join("")
    );
  };

  const vStripes = (colors) => {
    const w = 24 / colors.length;
    return svg(
      colors.map((c, i) => `<rect x="${(i * w).toFixed(2)}" width="${(w + 0.1).toFixed(2)}" height="16" fill="${c}"/>`).join("")
    );
  };

  const FLAGS = {
    US: svg(
      '<rect width="24" height="16" fill="#fff"/>' +
      '<g fill="#B22234">' +
      '<rect y="0" width="24" height="1.3"/><rect y="2.5" width="24" height="1.3"/>' +
      '<rect y="5" width="24" height="1.3"/><rect y="7.5" width="24" height="1.3"/>' +
      '<rect y="10" width="24" height="1.3"/><rect y="12.5" width="24" height="1.3"/>' +
      '<rect y="14.8" width="24" height="1.3"/></g>' +
      '<rect width="10.5" height="8.8" fill="#3C3B6E"/>' +
      '<g fill="#fff">' +
      '<circle cx="2" cy="1.8" r=".55"/><circle cx="4.3" cy="1.8" r=".55"/><circle cx="6.6" cy="1.8" r=".55"/><circle cx="8.8" cy="1.8" r=".55"/>' +
      '<circle cx="3.1" cy="3.6" r=".55"/><circle cx="5.4" cy="3.6" r=".55"/><circle cx="7.7" cy="3.6" r=".55"/>' +
      '<circle cx="2" cy="5.4" r=".55"/><circle cx="4.3" cy="5.4" r=".55"/><circle cx="6.6" cy="5.4" r=".55"/><circle cx="8.8" cy="5.4" r=".55"/>' +
      '<circle cx="3.1" cy="7.2" r=".55"/><circle cx="5.4" cy="7.2" r=".55"/><circle cx="7.7" cy="7.2" r=".55"/></g>'
    ),
    TW: svg(
      '<rect width="24" height="16" fill="#FE0000"/>' +
      '<rect width="12" height="8.5" fill="#000095"/>' +
      '<polygon points="6,1.5 6.7,3.1 8.4,2.5 7.5,4 9,4.9 7.3,5.2 7.8,6.8 6.3,5.9 5.5,7.4 5.1,5.7 3.5,6.1 4.4,4.7 3,3.8 4.7,3.5 4.2,1.9 5.7,2.8" fill="#fff"/>' +
      '<circle cx="6" cy="4.4" r="1.45" fill="#000095"/><circle cx="6" cy="4.4" r="1.15" fill="#fff"/>'
    ),
    JP: svg('<rect width="24" height="16" fill="#fff"/><circle cx="12" cy="8" r="4.6" fill="#BC002D"/>'),
    SG: svg(
      '<rect width="24" height="8" fill="#EF3340"/><rect y="8" width="24" height="8" fill="#fff"/>' +
      '<circle cx="5.8" cy="4" r="2.7" fill="#fff"/><circle cx="6.7" cy="4" r="2.2" fill="#EF3340"/>' +
      '<g fill="#fff"><circle cx="8.6" cy="2.5" r=".48"/><circle cx="9.8" cy="3.5" r=".48"/><circle cx="9.3" cy="4.9" r=".48"/><circle cx="7.9" cy="4.9" r=".48"/><circle cx="7.4" cy="3.5" r=".48"/></g>'
    ),
    HK: svg(
      '<rect width="24" height="16" fill="#DE2910"/>' +
      '<g transform="translate(12,8)" fill="#fff">' +
      '<ellipse cx="0" cy="-3.1" rx="1.2" ry="2.2" transform="rotate(0)"/>' +
      '<ellipse cx="0" cy="-3.1" rx="1.2" ry="2.2" transform="rotate(72)"/>' +
      '<ellipse cx="0" cy="-3.1" rx="1.2" ry="2.2" transform="rotate(144)"/>' +
      '<ellipse cx="0" cy="-3.1" rx="1.2" ry="2.2" transform="rotate(216)"/>' +
      '<ellipse cx="0" cy="-3.1" rx="1.2" ry="2.2" transform="rotate(288)"/>' +
      '<circle r="1" fill="#DE2910"/></g>'
    ),
    KR: svg(
      '<rect width="24" height="16" fill="#fff"/>' +
      '<circle cx="12" cy="8" r="3.8" fill="#CD2E3A"/>' +
      '<path d="M8.2,8 A3.8,3.8 0 0,0 15.8,8 A1.9,1.9 0 0,0 12,8 A1.9,1.9 0 0,1 8.2,8 Z" fill="#0047A0"/>' +
      '<g stroke="#111" stroke-width=".9">' +
      '<line x1="4" y1="4.8" x2="6.8" y2="2.8"/><line x1="4.7" y1="5.7" x2="7.5" y2="3.7"/>' +
      '<line x1="17.2" y1="2.8" x2="20" y2="4.8"/><line x1="16.5" y1="3.7" x2="19.3" y2="5.7"/>' +
      '<line x1="4" y1="11.2" x2="6.8" y2="13.2"/><line x1="4.7" y1="10.3" x2="7.5" y2="12.3"/>' +
      '<line x1="17.2" y1="13.2" x2="20" y2="11.2"/><line x1="16.5" y1="12.3" x2="19.3" y2="10.3"/></g>'
    ),
    GB: svg(
      '<rect width="24" height="16" fill="#012169"/>' +
      '<path d="M0,0 L24,16 M24,0 L0,16" stroke="#fff" stroke-width="3"/>' +
      '<path d="M0,0 L24,16 M24,0 L0,16" stroke="#C8102E" stroke-width="1.3"/>' +
      '<path d="M12,0 V16 M0,8 H24" stroke="#fff" stroke-width="4.4"/>' +
      '<path d="M12,0 V16 M0,8 H24" stroke="#C8102E" stroke-width="2.4"/>'
    ),
    DE: hStripes(["#111111", "#DD0000", "#FFCE00"]),
    FR: vStripes(["#002395", "#FFFFFF", "#ED2939"]),
    NL: hStripes(["#AE1C28", "#FFFFFF", "#21468B"]),
    IT: vStripes(["#009246", "#FFFFFF", "#CE2B37"]),
    IE: vStripes(["#169B62", "#FFFFFF", "#FF883E"]),
    PL: hStripes(["#FFFFFF", "#DC143C"]),
    ID: hStripes(["#CE1126", "#FFFFFF"]),
    UA: hStripes(["#0057B7", "#FFD700"]),
    RU: hStripes(["#FFFFFF", "#0039A6", "#D52B1E"]),
    ES: svg('<rect width="24" height="16" fill="#AA151B"/><rect y="4" width="24" height="8" fill="#F1BF00"/><rect x="6" y="6" width="2.4" height="4" rx=".5" fill="#AA151B"/>'),
    CA: svg(
      '<rect width="24" height="16" fill="#fff"/>' +
      '<rect width="6" height="16" fill="#FF0000"/><rect x="18" width="6" height="16" fill="#FF0000"/>' +
      '<path d="M12,3.4 L13,6.1 L15.2,5.6 L14.1,7.8 L15.6,8.8 L13.4,9.6 L13.7,11 L12.4,10.5 V12.8 H11.6 V10.5 L10.3,11 L10.6,9.6 L8.4,8.8 L9.9,7.8 L8.8,5.6 L11,6.1 Z" fill="#FF0000"/>'
    ),
    AU: svg(
      '<rect width="24" height="16" fill="#00008B"/>' +
      '<rect width="11" height="8" fill="#012169"/>' +
      '<path d="M0,0 L11,8 M11,0 L0,8" stroke="#fff" stroke-width="1.5"/>' +
      '<path d="M5.5,0 V8 M0,4 H11" stroke="#fff" stroke-width="2.2"/>' +
      '<path d="M5.5,0 V8 M0,4 H11" stroke="#C8102E" stroke-width="1.2"/>' +
      '<g fill="#fff"><circle cx="5.5" cy="12" r="1.4"/><circle cx="17.5" cy="4" r=".9"/><circle cx="20.2" cy="6.8" r=".9"/><circle cx="15.2" cy="7.6" r=".9"/><circle cx="17.8" cy="11.6" r="1"/><circle cx="19.5" cy="9.5" r=".6"/></g>'
    ),
    NZ: svg(
      '<rect width="24" height="16" fill="#00247D"/>' +
      '<rect width="11" height="8" fill="#012169"/>' +
      '<path d="M0,0 L11,8 M11,0 L0,8" stroke="#fff" stroke-width="1.5"/>' +
      '<path d="M5.5,0 V8 M0,4 H11" stroke="#fff" stroke-width="2.2"/>' +
      '<path d="M5.5,0 V8 M0,4 H11" stroke="#CC142B" stroke-width="1.2"/>' +
      '<g fill="#CC142B" stroke="#fff" stroke-width=".4"><circle cx="17.8" cy="3.6" r=".95"/><circle cx="20.5" cy="6.8" r=".95"/><circle cx="15.3" cy="7.4" r=".95"/><circle cx="17.8" cy="12" r="1.05"/></g>'
    ),
    CH: svg('<rect width="24" height="16" fill="#D52B1E"/><rect x="10.2" y="3.5" width="3.6" height="9" fill="#fff"/><rect x="7.5" y="6.2" width="9" height="3.6" fill="#fff"/>'),
    SE: svg('<rect width="24" height="16" fill="#006AA7"/><rect x="7" width="3" height="16" fill="#FECC00"/><rect y="6.5" width="24" height="3" fill="#FECC00"/>'),
    NO: svg('<rect width="24" height="16" fill="#BA0C2F"/><rect x="6.5" width="4" height="16" fill="#fff"/><rect y="6" width="24" height="4" fill="#fff"/><rect x="7.5" width="2" height="16" fill="#00205B"/><rect y="7" width="24" height="2" fill="#00205B"/>'),
    FI: svg('<rect width="24" height="16" fill="#fff"/><rect x="7" width="3.4" height="16" fill="#003580"/><rect y="6.3" width="24" height="3.4" fill="#003580"/>'),
    VN: svg('<rect width="24" height="16" fill="#DA251D"/><polygon points="12,3.4 13.1,6.8 16.7,6.8 13.8,8.9 14.9,12.3 12,10.2 9.1,12.3 10.2,8.9 7.3,6.8 10.9,6.8" fill="#FFFF00"/>'),
    MY: svg(
      '<rect width="24" height="16" fill="#fff"/>' +
      '<g fill="#CC0001"><rect y="0" width="24" height="1.3"/><rect y="2.6" width="24" height="1.3"/><rect y="5.2" width="24" height="1.3"/><rect y="7.8" width="24" height="1.3"/><rect y="10.4" width="24" height="1.3"/><rect y="13" width="24" height="1.3"/></g>' +
      '<rect width="12" height="9" fill="#010066"/>' +
      '<circle cx="5.2" cy="4.5" r="2.7" fill="#FFCC00"/><circle cx="6.1" cy="4.5" r="2.2" fill="#010066"/><circle cx="8.6" cy="4.5" r="1.4" fill="#FFCC00"/>'
    ),
    TH: svg('<rect width="24" height="16" fill="#A51931"/><rect y="2.7" width="24" height="10.6" fill="#F4F5F8"/><rect y="5.3" width="24" height="5.4" fill="#2D2A4A"/>'),
    IN: svg('<rect width="24" height="5.4" fill="#FF9933"/><rect y="5.3" width="24" height="5.4" fill="#fff"/><rect y="10.6" width="24" height="5.4" fill="#138808"/><circle cx="12" cy="8" r="2" fill="none" stroke="#000080" stroke-width=".75"/>'),
    PH: svg('<rect width="24" height="8" fill="#0038A8"/><rect y="8" width="24" height="8" fill="#CE1126"/><polygon points="0,0 10.5,8 0,16" fill="#fff"/><circle cx="3.8" cy="8" r="1.7" fill="#FCD116"/>'),
    BR: svg('<rect width="24" height="16" fill="#009B3A"/><polygon points="12,2 21.5,8 12,14 2.5,8" fill="#FEDF00"/><circle cx="12" cy="8" r="3.4" fill="#002776"/><path d="M8.8,7.4 Q12,6.4 15.2,8.4" stroke="#fff" stroke-width=".7" fill="none"/>'),
    TR: svg('<rect width="24" height="16" fill="#E30A17"/><circle cx="9.6" cy="8" r="3.8" fill="#fff"/><circle cx="10.8" cy="8" r="3.1" fill="#E30A17"/><polygon points="14.5,6.2 15,7.6 16.5,7.6 15.3,8.5 15.8,9.9 14.5,9 13.2,9.9 13.7,8.5 12.5,7.6 14,7.6" fill="#fff"/>'),
    CN: svg(
      '<rect width="24" height="16" fill="#DE2910"/>' +
      '<polygon points="4.8,2.2 5.4,4 7.3,4 5.8,5.1 6.4,6.9 4.8,5.8 3.2,6.9 3.8,5.1 2.3,4 4.2,4" fill="#FFDE00"/>' +
      '<g fill="#FFDE00"><circle cx="8.8" cy="2.2" r=".6"/><circle cx="10" cy="3.6" r=".6"/><circle cx="10" cy="5.4" r=".6"/><circle cx="8.8" cy="6.8" r=".6"/></g>'
    ),
    MO: svg('<rect width="24" height="16" fill="#00785E"/><circle cx="12" cy="9.5" r="3.2" fill="#fff"/><g fill="#FFDE00"><circle cx="12" cy="4" r=".8"/><circle cx="9.4" cy="5" r=".55"/><circle cx="14.6" cy="5" r=".55"/></g>'),
    AE: svg('<rect width="24" height="5.4" fill="#00732F"/><rect y="5.3" width="24" height="5.4" fill="#fff"/><rect y="10.6" width="24" height="5.4" fill="#000"/><rect width="6.5" height="16" fill="#FF0000"/>'),
  };

  window.renderCountryFlag = function renderCountryFlag(countryCode) {
    const code = String(countryCode || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(code)) return "";
    if (Object.prototype.hasOwnProperty.call(FLAGS, code)) {
      return FLAGS[code];
    }
    return `<span class="flag-fallback">${code}</span>`;
  };
})();
