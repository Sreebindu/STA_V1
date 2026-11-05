"use client";
import {
  Fragment,
  useState,
  useEffect,
  useLayoutEffect,
  useMemo,
  useCallback,
} from "react";
import { useMap } from "react-leaflet";
import dynamic from "next/dynamic";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Search,
  Globe,
  Map as MapIcon,
  MapPin,
  Radio,
  Activity,
  Zap,
} from "lucide-react";
import "leaflet/dist/leaflet.css";
import "react-leaflet-cluster/dist/assets/MarkerCluster.Default.css";
import "react-leaflet-cluster/dist/assets/MarkerCluster.css";
import "flag-icons/css/flag-icons.min.css";
import {
  getCountryDisplayName,
  getCountryCode,
} from "@/constants/countryMapping";
import {
  getCountryColor,
  getCountryMarkerColor,
  getCountryDataForFeature,
  INDIA_LAND_COLOR,
} from "./countryColors";
import {
  buildSummaryMarkerGroups,
} from "./summaryMarkerColors";
import PropTypes from "prop-types";

const MapContainer = dynamic(
  () => import("react-leaflet").then((mod) => mod.MapContainer),
  { ssr: false },
);
const CesiumGlobe = dynamic(() => import("./CesiumGlobe"), { ssr: false });
const ZoomControl = dynamic(
  () => import("react-leaflet").then((mod) => mod.ZoomControl),
  { ssr: false },
);
const Marker = dynamic(
  () => import("react-leaflet").then((mod) => mod.Marker),
  { ssr: false },
);
const Tooltip = dynamic(
  () => import("react-leaflet").then((mod) => mod.Tooltip),
  { ssr: false },
);
const Polyline = dynamic(
  () => import("react-leaflet").then((mod) => mod.Polyline),
  { ssr: false },
);
const GeoJSON = dynamic(
  () => import("react-leaflet").then((mod) => mod.GeoJSON),
  { ssr: false },
);

function MapZoomListener({ setZoomLevel }) {
  const map = useMap();
  useEffect(() => {
    const updateZoom = () => setZoomLevel(map.getZoom());
    updateZoom();
    map.on("zoomend", updateZoom);
    return () => map.off("zoomend", updateZoom);
  }, [map, setZoomLevel]);
  return null;
}

function MapViewportListener({ setViewport }) {
  const map = useMap();

  useEffect(() => {
    const updateViewport = () => {
      const bounds = map.getBounds();
      const size = map.getSize();

      setViewport({
        zoom: map.getZoom(),
        north: bounds.getNorth(),
        south: bounds.getSouth(),
        east: bounds.getEast(),
        west: bounds.getWest(),
        width: size.x,
        height: size.y,
      });
    };

    updateViewport();
    map.on("moveend zoomend resize", updateViewport);
    return () => map.off("moveend zoomend resize", updateViewport);
  }, [map, setViewport]);

  return null;
}

function PcapDrillDownController({ focusRequest, mode }) {
  const map = useMap();

  useEffect(() => {
    if (mode !== "pcap" || !focusRequest) return;

    const currentZoom = map.getZoom();
    const nextZoom = getPcapDrillDownZoom(currentZoom);

    if (nextZoom <= currentZoom) return;

    map.flyTo([focusRequest.lat, focusRequest.lng], nextZoom, {
      duration: 0.7,
      easeLinearity: 0.2,
    });
  }, [focusRequest, map, mode]);

  return null;
}

function EnsureTopPane() {
  const map = useMap();
  useLayoutEffect(() => {
    const geoPane = map.getPane("geoPane") || map.createPane("geoPane");
    geoPane.style.zIndex = "300";
    geoPane.style.pointerEvents = "auto";

    const indiaPane = map.getPane("indiaPane") || map.createPane("indiaPane");
    indiaPane.style.zIndex = "350";
    indiaPane.style.pointerEvents = "auto";

    const topPane = map.getPane("topPane") || map.createPane("topPane");
    topPane.style.zIndex = "700";
    topPane.style.pointerEvents = "auto";
  }, [map]);
  return null;
}

function MapResetControl({ L, center, zoom }) {
  const map = useMap();

  useEffect(() => {
    if (!L || !map) return;

    const control = L.control({ position: "bottomright" });

    control.onAdd = () => {
      const container = L.DomUtil.create(
        "div",
        "leaflet-bar map-controls-stack",
      );

      // =========================
      // ZOOM IN
      // =========================
      const zoomIn = L.DomUtil.create("a", "map-control-button", container);

      zoomIn.href = "#";
      zoomIn.title = "Zoom in";
      zoomIn.setAttribute("aria-label", "Zoom in");
      zoomIn.setAttribute("role", "button");
      zoomIn.innerHTML = "+";

      L.DomEvent.on(zoomIn, "click", (event) => {
        L.DomEvent.stop(event);
        map.zoomIn();
      });

      // =========================
      // ZOOM OUT
      // =========================
      const zoomOut = L.DomUtil.create("a", "map-control-button", container);

      zoomOut.href = "#";
      zoomOut.title = "Zoom out";
      zoomOut.setAttribute("aria-label", "Zoom out");
      zoomOut.setAttribute("role", "button");
      zoomOut.innerHTML = "−";

      L.DomEvent.on(zoomOut, "click", (event) => {
        L.DomEvent.stop(event);
        map.zoomOut();
      });

      // =========================
      // RESET MAP
      // =========================
      const reset = L.DomUtil.create(
        "a",
        "map-control-button map-reset-button",
        container,
      );

      reset.href = "#";
      reset.title = "Reset map view";
      reset.setAttribute("aria-label", "Reset map view");
      reset.setAttribute("role", "button");

      reset.innerHTML = `
        <svg
          viewBox="0 0 24 24"
          width="16"
          height="16"
          aria-hidden="true"
        >
          <circle
            cx="12"
            cy="12"
            r="7.5"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
          />

          <circle
            cx="12"
            cy="12"
            r="2.5"
            fill="currentColor"
          />

          <path
            d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
            stroke-linecap="round"
          />
        </svg>
      `;

      L.DomEvent.on(reset, "click", (event) => {
        L.DomEvent.stop(event);

        map.flyTo(center, zoom, {
          duration: 0.5,
          easeLinearity: 0.2,
        });
      });

      // Prevent map dragging/scrolling when using controls
      L.DomEvent.disableClickPropagation(container);
      L.DomEvent.disableScrollPropagation(container);

      return container;
    };

    control.addTo(map);

    return () => {
      control.remove();
    };
  }, [L, map, center, zoom]);

  return null;
}
const DEFAULT_MAP_CENTER = [25, 20];
const DELHI_COORDS = [28.6139, 77.209];

const SUMMARY_DOT_CLASSES =
  "rounded-full border-2 border-white bg-blue-600 shadow-[0_0_15px_rgba(37,99,235,0.4),0_0_30px_rgba(37,99,235,0.1)] transition-all duration-200 ease-out cursor-pointer animate-[summary-scale-breathe_2s_ease-in-out_infinite] hover:!bg-white hover:![transform:scale(3)] hover:![box-shadow:0_0_50px_rgba(37,99,235,1)] hover:!z-[1000] hover:!border-[2.5px] hover:!border-blue-600";

const CENTER_DOT_CLASSES =
  "w-3 h-3 rounded-full bg-red-500 border-2 border-white shadow-[0_6px_18px_rgba(239,68,68,0.28)]";

const CONTINENT_LABEL_BASE_CLASSES =
  "-translate-x-1/2 -translate-y-1/2 whitespace-pre-line text-center font-extrabold uppercase tracking-[0.03em] leading-[0.95] select-none pointer-events-none";

const hasCoordinates = (ip) => {
  const lat = Number(ip.latitude);
  const lng = Number(ip.longitude);
  return Number.isFinite(lat) && Number.isFinite(lng);
};

const getPcapMaxPoints = (zoomLevel, totalIpCount) => {
  if (totalIpCount > 10000) {
    if (zoomLevel >= 10) return 420;
    if (zoomLevel >= 8) return 360;
    if (zoomLevel >= 6) return 300;
    if (zoomLevel >= 4) return 240;
    return 180;
  }

  if (totalIpCount > 3000) {
    if (zoomLevel >= 9) return 420;
    if (zoomLevel >= 7) return 360;
    if (zoomLevel >= 5) return 300;
    return 240;
  }

  return 420;
};

const getPcapScreenSpacing = (zoomLevel, totalIpCount) => {
  let spacing;

  if (zoomLevel >= 11) spacing = 22;
  else if (zoomLevel >= 9) spacing = 28;
  else if (zoomLevel >= 7) spacing = 36;
  else if (zoomLevel >= 5) spacing = 46;
  else if (zoomLevel >= 3) spacing = 58;
  else spacing = 72;

  if (totalIpCount > 10000 && zoomLevel < 7) spacing += 10;
  else if (totalIpCount > 3000 && zoomLevel < 5) spacing += 6;

  return spacing;
};

const clampLatitudeForProjection = (lat) =>
  Math.max(-85.05112878, Math.min(85.05112878, lat));

const mercatorY = (lat) => {
  const radians = (clampLatitudeForProjection(lat) * Math.PI) / 180;
  return (
    (1 - Math.log(Math.tan(radians) + 1 / Math.cos(radians)) / Math.PI) / 2
  );
};

const getViewportLongitudeInfo = (west, east) => {
  let normalizedWest = west;
  let normalizedEast = east;

  while (normalizedEast < normalizedWest) {
    normalizedEast += 360;
  }

  const span = Math.max(normalizedEast - normalizedWest, 0.000001);
  return { west: normalizedWest, east: normalizedEast, span };
};

const getLongitudeInViewport = (lng, west, east) => {
  const info = getViewportLongitudeInfo(west, east);
  let normalized = lng;

  while (normalized < info.west) normalized += 360;
  while (normalized > info.east) normalized -= 360;

  return normalized;
};

const isInsideViewport = (ip, viewport) => {
  if (!viewport) return true;

  const lat = Number(ip.latitude);
  const lng = Number(ip.longitude);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) return false;

  const latPad = Math.max(
    0.5,
    Math.abs(viewport.north - viewport.south) * 0.04,
  );
  const longitudeInfo = getViewportLongitudeInfo(viewport.west, viewport.east);
  const lngPad = Math.max(0.5, longitudeInfo.span * 0.04);
  const adjustedLng = getLongitudeInViewport(lng, viewport.west, viewport.east);

  return (
    lat >= viewport.south - latPad &&
    lat <= viewport.north + latPad &&
    adjustedLng >= longitudeInfo.west - lngPad &&
    adjustedLng <= longitudeInfo.east + lngPad
  );
};

const getScreenPosition = (lat, lng, viewport) => {
  if (!viewport || !viewport.width || !viewport.height) return null;

  const adjustedLng = getLongitudeInViewport(lng, viewport.west, viewport.east);
  const longitudeInfo = getViewportLongitudeInfo(viewport.west, viewport.east);
  const x =
    ((adjustedLng - longitudeInfo.west) / longitudeInfo.span) * viewport.width;

  const northY = mercatorY(viewport.north);
  const southY = mercatorY(viewport.south);
  const pointY = mercatorY(lat);
  const ySpan = Math.max(southY - northY, 0.000001);

  const y = ((pointY - northY) / ySpan) * viewport.height;

  return { x, y };
};

const createIndividualPcapPoint = (ip, idx) => ({
  id: `ip-${ip.ip || idx}`,
  lat: Number(ip.latitude),
  lng: Number(ip.longitude),
  city: ip.city || "Unknown",
  country: ip.country || "Unknown",
  ips: [ip],
  count: 1,
  totalPackets: Number(ip.packet_count) || 0,
  isExactCoordinateGroup: true,
  exactCoordinateGroupCount: 1,
});

/*
 * IMPORTANT:
 * Two different concepts are kept separate here:
 *
 * 1. Exact-coordinate grouping:
 *    If multiple IP records have the exact same latitude + longitude,
 *    they MUST become one point and one details card.
 *
 * 2. Screen-space clustering:
 *    At lower zoom levels we may visually cluster nearby exact-coordinate
 *    groups for performance. This is only a temporary map cluster. It is
 *    NOT treated as one real location. Clicking it drills down instead of
 *    opening a combined card for nearby locations.
 */
const groupIpsByExactCoordinates = (ips) => {
  const groups = new Map();

  ips.forEach((ip, idx) => {
    const lat = Number(ip.latitude);
    const lng = Number(ip.longitude);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;

    const key = `${lat},${lng}`;
    const existing = groups.get(key);

    if (existing) {
      existing.ips.push(ip);
      existing.count += 1;
      existing.totalPackets += Number(ip.packet_count) || 0;
      return;
    }

    groups.set(key, {
      id: `exact-${key}`,
      lat,
      lng,
      city: ip.city || "Unknown",
      country: ip.country || "Unknown",
      ips: [ip],
      count: 1,
      totalPackets: Number(ip.packet_count) || 0,
      firstIndex: idx,
      isExactCoordinateGroup: true,
      exactCoordinateGroupCount: 1,
    });
  });

  return Array.from(groups.values()).sort(
    (a, b) => a.firstIndex - b.firstIndex,
  );
};

const groupIpsByScreenSpacing = (coordinateGroups, viewport, spacing) => {
  if (!viewport || !viewport.width || !viewport.height) {
    return [];
  }

  const groups = new Map();

  coordinateGroups.forEach((coordinateGroup, idx) => {
    const lat = Number(coordinateGroup.lat);
    const lng = Number(coordinateGroup.lng);
    const screen = getScreenPosition(lat, lng, viewport);

    if (!screen) return;

    const cellX = Math.floor(screen.x / spacing);
    const cellY = Math.floor(screen.y / spacing);
    const key = `${cellX}:${cellY}`;

    const existing = groups.get(key);

    if (existing) {
      existing.latTotal += lat * coordinateGroup.count;
      existing.lngTotal += lng * coordinateGroup.count;
      existing.count += coordinateGroup.count;
      existing.totalPackets += coordinateGroup.totalPackets;
      existing.ips.push(...coordinateGroup.ips);
      existing.exactCoordinateGroupCount += 1;
      existing.isExactCoordinateGroup = false;
      return;
    }

    groups.set(key, {
      id: `screen-${key}`,
      latTotal: lat * coordinateGroup.count,
      lngTotal: lng * coordinateGroup.count,
      count: coordinateGroup.count,
      city: coordinateGroup.city || "Unknown",
      country: coordinateGroup.country || "Unknown",
      ips: [...coordinateGroup.ips],
      totalPackets: coordinateGroup.totalPackets,
      firstIndex: idx,
      isExactCoordinateGroup: true,
      exactCoordinateGroupCount: 1,
    });
  });

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      lat: group.latTotal / Math.max(group.count, 1),
      lng: group.lngTotal / Math.max(group.count, 1),
    }))
    .sort((a, b) => a.firstIndex - b.firstIndex);
};

const buildPcapMapPoints = (ips, zoomLevel, viewport) => {
  const totalIpCount = ips.length;
  if (!totalIpCount) return [];

  const visibleIps = viewport
    ? ips.filter((ip) => isInsideViewport(ip, viewport))
    : ips;

  if (!visibleIps.length) return [];

  /*
   * First and most importantly, collapse only records that have the
   * EXACT same coordinates. This prevents the "1 + 1 on top of each
   * other" problem at high zoom.
   */
  const exactCoordinateGroups = groupIpsByExactCoordinates(visibleIps);
  if (!exactCoordinateGroups.length) return [];

  /*
   * At the deepest zoom level we do NOT perform screen clustering.
   * Every exact coordinate remains its own marker. Therefore:
   *
   *   same coordinates -> one marker containing all IPs
   *   nearby coordinates -> separate markers
   */
  if (zoomLevel >= 12) {
    return exactCoordinateGroups;
  }

  const maxPoints = getPcapMaxPoints(zoomLevel, totalIpCount);

  let spacing = getPcapScreenSpacing(zoomLevel, totalIpCount);
  let groupedPoints = groupIpsByScreenSpacing(
    exactCoordinateGroups,
    viewport,
    spacing,
  );

  if (!groupedPoints.length) {
    return exactCoordinateGroups.slice(0, maxPoints);
  }

  let safety = 0;
  while (groupedPoints.length > maxPoints && safety < 12) {
    spacing *= 1.18;
    groupedPoints = groupIpsByScreenSpacing(
      exactCoordinateGroups,
      viewport,
      spacing,
    );
    safety += 1;
  }

  return groupedPoints;
};

const getPcapDrillDownZoom = (currentZoom) => {
  if (currentZoom < 4) return 5;
  if (currentZoom < 6) return 7;
  if (currentZoom < 8) return 9;
  if (currentZoom < 10) return 11;
  if (currentZoom < 12) return 12;
  return currentZoom;
};

const SIGNAL_COLORS = {
  cool: {
    marker: "#22d3ee",
    halo: "rgba(34, 211, 238, 0.24)",
    pulse: "rgba(34, 211, 238, 0.4)",
    line: "#06b6d4",
    shadow: "rgba(8, 145, 178, 0.4)",
  },
  mid: {
    marker: "#34d399",
    halo: "rgba(52, 211, 153, 0.24)",
    pulse: "rgba(52, 211, 153, 0.4)",
    line: "#059669",
    shadow: "rgba(5, 150, 105, 0.4)",
  },
  warm: {
    marker: "#fbbf24",
    halo: "rgba(251, 191, 36, 0.26)",
    pulse: "rgba(251, 191, 36, 0.42)",
    line: "#d97706",
    shadow: "rgba(217, 119, 6, 0.42)",
  },
  hot: {
    marker: "#f43f5e",
    halo: "rgba(244, 63, 94, 0.26)",
    pulse: "rgba(244, 63, 94, 0.42)",
    line: "#e11d48",
    shadow: "rgba(225, 29, 72, 0.44)",
  },
};

const buildGlowShadow = (style) =>
  `0 0 0 4px ${style.halo}, 0 0 26px 7px ${style.pulse}, 0 8px 18px ${style.shadow}`;

const getPcapPointStyle = (count) => {
  if (count >= 200) return SIGNAL_COLORS.hot;
  if (count >= 10) return SIGNAL_COLORS.warm;
  if (count >= 2) return SIGNAL_COLORS.mid;
  return SIGNAL_COLORS.cool;
};

const REPORT_MARKER_COLORS = {
  fill: "#2563eb",
  shadow: "rgba(30, 64, 175, 0.30)",
  hoverShadow: "rgba(30, 64, 175, 0.38)",
};

const CONTINENT_LABELS = [
  {
    id: "north-america",
    text: "North\nAmerica",
    position: [48, -105],
    className: "label-large",
  },
  {
    id: "europe",
    text: "Europe",
    position: [53, 15],
    className: "label-large",
  },

  { id: "africa", text: "Africa", position: [5, 18], className: "label-large" },
  { id: "asia", text: "Asia", position: [42, 78], className: "label-large" },
  {
    id: "south-america",
    text: "South America",
    position: [-14, -65],
    className: "label-large",
  },
  {
    id: "australia",
    text: "Australia",
    position: [-25, 133],
    className: "label-large",
  },
  {
    id: "antarctica",
    text: "Antarctica",
    position: [-80, 0],
    className: "label-large",
  },
];

const getPcapMarkerSize = (count, zoomLevel) => {
  const zoomBoost = zoomLevel >= 7 ? 2 : 0;
  return Math.min(34 + zoomBoost, Math.max(18, 17 + Math.log10(count) * 6));
};

const getPcapLineStyle = (count, zoomLevel) => {
  const scale = Math.min(1, Math.max(0, Math.log10(count + 1) / 3));

  return {
    trackWeight: zoomLevel >= 6 ? 2.7 : 2.2,
    trackOpacity: zoomLevel >= 6 ? 0.18 : 0.14,
    weight: zoomLevel >= 6 ? 1.45 + scale * 0.6 : 1.15 + scale * 0.45,
    opacity: zoomLevel >= 6 ? 0.5 : 0.38,
  };
};

function ContinentLabels({ L, labels, zoomLevel }) {
  if (!L) return null;
  if (typeof zoomLevel === "number" && zoomLevel >= 6) return null;

  return labels.map((label) => {
    const icon = L.divIcon({
      html: `<div class="continent-label ${label.className}">${label.text.replace(/\n/g, "<br/>")}</div>`,
      className: "continent-label-marker",
      iconSize: [1, 1],
      iconAnchor: [0, 0],
    });

    return (
      <Marker
        key={label.id}
        position={label.position}
        icon={icon}
        interactive={false}
      />
    );
  });
}

const unwrapRingLongitudes = (ring) => {
  let offset = 0;
  let prevLng = null;
  const unwrapped = ring.map(([lng, lat]) => {
    if (prevLng !== null) {
      const delta = lng + offset - prevLng;
      if (delta > 180) offset -= 360;
      else if (delta < -180) offset += 360;
    }
    const adjusted = lng + offset;
    prevLng = adjusted;
    return [adjusted, lat];
  });

  let min = Infinity;
  let max = -Infinity;
  for (const [lng] of unwrapped) {
    if (lng < min) min = lng;
    if (lng > max) max = lng;
  }
  if (max - min > 380) return ring;
  return unwrapped;
};

const unwrapAntimeridianGeometry = (geometry) => {
  if (!geometry) return geometry;
  if (geometry.type === "Polygon") {
    return {
      ...geometry,
      coordinates: geometry.coordinates.map(unwrapRingLongitudes),
    };
  }
  if (geometry.type === "MultiPolygon") {
    return {
      ...geometry,
      coordinates: geometry.coordinates.map((poly) =>
        poly.map(unwrapRingLongitudes),
      ),
    };
  }
  return geometry;
};

const sanitizeWorldGeoJSON = (geojson) => {
  if (!geojson || !Array.isArray(geojson.features)) return geojson;
  return {
    ...geojson,
    features: geojson.features.map((feature) => ({
      ...feature,
      geometry: unwrapAntimeridianGeometry(feature.geometry),
    })),
  };
};

const SUMMARY_LAND_FILL = "#f2efe9";
const SUMMARY_BORDER_COLOR = "#ddebeea2";

const getSummaryLandStyle = () => ({
  color: SUMMARY_BORDER_COLOR,
  weight: 0.8,
  opacity: 1,
  fillColor: SUMMARY_LAND_FILL,
  fillOpacity: 1,
  lineCap: "round",
  lineJoin: "round",
  smoothFactor: 0,
});

const getIndiaBoundaryStyle = (fillColor = SUMMARY_LAND_FILL) => ({
  color: SUMMARY_BORDER_COLOR,
  weight: 0.8,
  opacity: 1,
  fillColor,
  fillOpacity: 1,
  lineCap: "round",
  lineJoin: "round",
  smoothFactor: 0,
});

const SUMMARY_MAP_BACKGROUND = "#aad3df";
const formatCompactCount = (count) => {
  const value = Number(count) || 0;
  if (value >= 1_000_000) {
    const scaled = value / 1_000_000;
    return `${scaled >= 10 ? Math.round(scaled) : scaled.toFixed(1).replace(/\.0$/, "")}M`;
  }
  if (value >= 1_000) {
    const scaled = value / 1_000;
    return `${scaled >= 10 ? Math.round(scaled) : scaled.toFixed(1).replace(/\.0$/, "")}K`;
  }
  return `${Math.round(value)}`;
};

const normalizeForMatch = (name) =>
  (name || "").toLowerCase().replace(/[^a-z0-9]/g, "");

const getMappedCountryName = (name) => getCountryDisplayName(name || "Unknown");

const GEOJSON_NAME_KEYS = [
  "ADMIN",
  "admin",
  "NAME",
  "name",
  "NAME_LONG",
  "name_long",
  "SOVEREIGNT",
  "sovereignt",
  "name_en",
];

const getFeatureNameCandidates = (properties) =>
  GEOJSON_NAME_KEYS.map((key) => properties?.[key]).filter(Boolean);

const GEOJSON_ISO2_KEYS = [
  "ISO_A2_EH",
  "iso_a2_eh",
  "ISO_A2",
  "iso_a2",
  "WB_A2",
  "wb_a2",
];

const getFeatureIso2 = (properties) => {
  if (!properties) return null;
  for (const key of GEOJSON_ISO2_KEYS) {
    const value = properties[key];
    if (
      value &&
      typeof value === "string" &&
      value.length === 2 &&
      value !== "-99"
    ) {
      return value.toLowerCase();
    }
  }
  return null;
};

const buildCountryIsoIndex = (worldCountries) => {
  const map = new Map();
  if (!worldCountries || !Array.isArray(worldCountries.features)) return map;

  worldCountries.features.forEach((feature) => {
    const props = feature.properties || {};
    const iso2 = getFeatureIso2(props);
    if (!iso2) return;
    getFeatureNameCandidates(props).forEach((candidate) => {
      const key = normalizeForMatch(candidate);
      if (key && !map.has(key)) map.set(key, iso2);
    });
  });

  return map;
};

const getCountryIso2 = (name, isoIndex) => {
  const mapped = getCountryCode(name);
  if (mapped) return mapped;

  if (!name || !isoIndex || !isoIndex.size) return null;
  const key = normalizeForMatch(name);
  if (isoIndex.has(key)) return isoIndex.get(key);
  for (const [candidateKey, iso2] of isoIndex.entries()) {
    if (candidateKey.includes(key) || key.includes(candidateKey)) return iso2;
  }
  return null;
};

function CountryFlag({ iso2, size = 20 }) {
  if (!iso2) {
    return <Globe size={size} className="text-blue-500" />;
  }
  return (
    <span
      className={`fi fi-${iso2}`}
      style={{
        width: size * 1.35,
        height: size,
        display: "inline-block",
        borderRadius: 4,
        backgroundSize: "cover",
      }}
    />
  );
}

CountryFlag.propTypes = {
  iso2: PropTypes.string,
  size: PropTypes.number,
};

const ringSignedArea = (ring) => {
  let area = 0;
  for (let i = 0, len = ring.length, j = len - 1; i < len; j = i++) {
    area += ring[j][0] * ring[i][1] - ring[i][0] * ring[j][1];
  }
  return area / 2;
};

const ringCentroid = (ring) => {
  let x = 0,
    y = 0,
    area = 0;
  for (let i = 0, len = ring.length, j = len - 1; i < len; j = i++) {
    const [x0, y0] = ring[j];
    const [x1, y1] = ring[i];
    const cross = x0 * y1 - x1 * y0;
    area += cross;
    x += (x0 + x1) * cross;
    y += (y0 + y1) * cross;
  }
  area *= 0.5;
  if (!area) return null;
  return [y / (6 * area), x / (6 * area)]; // [lat, lng]
};

const getPolygonCentroid = (geometry) => {
  if (!geometry) return null;
  if (geometry.type === "Polygon") {
    return ringCentroid(geometry.coordinates[0]);
  }
  if (geometry.type === "MultiPolygon") {
    let bestRing = null;
    let bestArea = -Infinity;
    geometry.coordinates.forEach((poly) => {
      const ring = poly[0];
      const area = Math.abs(ringSignedArea(ring));
      if (area > bestArea) {
        bestArea = area;
        bestRing = ring;
      }
    });
    return bestRing ? ringCentroid(bestRing) : null;
  }
  return null;
};

export function WorldMapLeaflet({
  externalIps = [],
  onIpClick,
  mode = "pcap",
  countryData = [],
  title,
  fallbackCountry,
  reportLabel,
  reportType,
  enableViewToggle = false,
  initialZoomOverride,
  minZoomOverride = 2,
  showPacketCounts = true,
}) {
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [selectedCountry, setSelectedCountry] = useState(null);
  const [hoveredCountry, setHoveredCountry] = useState(null);
  const [L, setL] = useState(null);
  const [indiaBorder, setIndiaBorder] = useState(null);
  const [worldCountries, setWorldCountries] = useState(null);
  const [zoomLevel, setZoomLevel] = useState(2);
  const [viewport, setViewport] = useState(null);
  const [mapView, setMapView] = useState("flat");

  useEffect(() => {
    import("leaflet").then((leaflet) => {
      setL(leaflet);
    });

    fetch("/india-border.json")
      .then((res) => res.json())
      .then((data) => setIndiaBorder(data))
      .catch((err) => console.error("Failed to load India border:", err));

    fetch("/world-countries.json")
      .then((res) => res.json())
      .then((data) => setWorldCountries(sanitizeWorldGeoJSON(data)))
      .catch((err) => console.error("Failed to load world countries:", err));
  }, []);

  const validIps = useMemo(() => {
    if (mode === "summary") return [];
    if (!externalIps.length) return [];
    return externalIps.filter(hasCoordinates);
  }, [externalIps, mode]);

  const reportsGroupedPoints = useMemo(() => {
    if (mode !== "reports") return [];
    const groups = new Map();
    validIps.forEach((ip) => {
      const lat = Number(ip.latitude);
      const lng = Number(ip.longitude);
      const key = `${lat},${lng}`;
      const country = ip.country || fallbackCountry;
      const countryName =
        typeof country === "string" ? country.trim() : String(country ?? "");
      const packetCount = Number(ip.packet_count ?? ip.packets);
      const hasPacketCount = Number.isFinite(packetCount);
      if (groups.has(key)) {
        const group = groups.get(key);
        group.count += 1;
        group.ips.push(ip);
        if (countryName && countryName.toLowerCase() !== "unknown") {
          group.countries.add(countryName);
        }
        if (hasPacketCount) group.totalPackets += packetCount;
        group.hasPacketCount ||= hasPacketCount;
      } else {
        groups.set(key, {
          id: key,
          lat,
          lng,
          city: reportLabel || ip.city || "Unknown",
          countries: new Set(
            countryName && countryName.toLowerCase() !== "unknown"
              ? [countryName]
              : [],
          ),
          country: "",
          categoryLabel: "",
          ips: [ip],
          count: 1,
          totalPackets: hasPacketCount ? packetCount : 0,
          hasPacketCount,
        });
      }
    });
    return Array.from(groups.values(), (group) => {
      const countries = Array.from(group.countries);
      const country =
        countries.length > 1 ? "Multiple countries" : countries[0] || "Unknown";
      const categoryLabel =
        reportType === "isp" ? reportLabel || "ISP" : country;

      return { ...group, country, categoryLabel };
    });
  }, [fallbackCountry, reportLabel, reportType, validIps, mode]);

  const [pcapDrillDownRequest, setPcapDrillDownRequest] = useState(null);

  const pcapMapPoints = useMemo(() => {
    if (mode !== "pcap") return [];
    return buildPcapMapPoints(validIps, zoomLevel, viewport);
  }, [mode, validIps, zoomLevel, viewport]);

  const pcapLinePoints = useMemo(() => {
    if (mode !== "pcap") return [];
    return pcapMapPoints;
  }, [mode, pcapMapPoints]);

  const pcapMarkerItems = useMemo(() => {
    if (!L || mode !== "pcap") return [];

    return pcapMapPoints.map((point, idx) => {
      const markerSize = getPcapMarkerSize(point.count, zoomLevel);
      const label = point.count.toLocaleString();
      const pointStyle = getPcapPointStyle(point.count);

      const jumpDelay =
        Math.abs(Math.round(point.lat * 13 + point.lng * 7 + idx * 3)) % 240;

      const deltaLng = DELHI_COORDS[1] - point.lng;
      const deltaLat = point.lat - DELHI_COORDS[0];
      const flyMagnitude = Math.max(Math.abs(deltaLng), Math.abs(deltaLat), 1);
      const jitterX = Math.sin(point.lat * 2.7 + point.lng) * 8;
      const jitterY = Math.cos(point.lng * 2.1 - point.lat) * 6;
      const sprinkleX = Math.round((deltaLng / flyMagnitude) * 34 + jitterX);
      const sprinkleY = Math.round((deltaLat / flyMagnitude) * 28 + jitterY);

      return {
        point,
        markerSize,
        icon: L.divIcon({
          html: `
            <div class="pcap-marker pcap-marker-sprinkle group" style="width: ${markerSize}px; height: ${markerSize}px; --sprinkle-x: ${sprinkleX}px; --sprinkle-y: ${sprinkleY}px; background: ${pointStyle.marker}; box-shadow: ${buildGlowShadow(pointStyle)}; animation-delay: ${jumpDelay}ms;">
              <div class="pcap-sprinkle-ring" style="background: ${pointStyle.marker};"></div>
              <span style="position: relative; z-index: 2; font-size: ${point.count > 999 ? 9 : 10}px;">${label}</span>
            </div>
          `,
          className: "",
          iconSize: [markerSize, markerSize],
          iconAnchor: [markerSize / 2, markerSize / 2],
        }),
      };
    });
  }, [L, mode, pcapMapPoints, zoomLevel]);

  const countryIsoIndex = useMemo(
    () => buildCountryIsoIndex(worldCountries),
    [worldCountries],
  );
  const handleGlobeCountrySelect = useCallback(
    (entry) => {
      const name = entry?.name || "Unknown";
      setSelectedCountry({
        name: getMappedCountryName(name),
        iso2: getCountryIso2(name, countryIsoIndex),
        count: entry?.count || 0,
        captures: entry?.captures_seen ?? entry?.captures ?? 0,
        packets: entry?.packets || 0,
      });
    },
    [countryIsoIndex],
  );
  const handleFlatCountrySelect = useCallback(
    (properties, fallbackName) => {
      const country = getCountryDataForFeature(properties, countryData);
      const name =
        country?.name ||
        fallbackName ||
        getFeatureNameCandidates(properties)[0] ||
        "Unknown";
      setSelectedCountry({
        name: getMappedCountryName(name),
        iso2: getCountryIso2(name, countryIsoIndex) || getFeatureIso2(properties),
        count: country?.count || 0,
        captures: country?.captures_seen ?? country?.captures ?? 0,
        packets: country?.packets || 0,
      });
    },
    [countryData, countryIsoIndex],
  );

  const indiaBoundaryRenderer = useMemo(
    () => (L ? L.svg({ pane: "indiaPane" }) : null),
    [L],
  );
  const worldRenderer = useMemo(
    () => (L ? L.svg({ pane: "geoPane" }) : null),
    [L],
  );

  const summaryMarkerEntries = useMemo(
    () =>
      mode === "summary"
        ? countryData.filter((entry) => (Number(entry.count) || 0) > 0)
        : [],
    [countryData, mode],
  );
  const summaryMarkerGroups = useMemo(
    () => buildSummaryMarkerGroups(),
    [],
  );
  const initialCenter = DEFAULT_MAP_CENTER;

  const initialZoom =
    initialZoomOverride ?? (mode === "summary" ? 2 : 2.2);

  const mapContainerStyle = {
    "--leaflet-bg": SUMMARY_MAP_BACKGROUND,
  };
  const mapShellClassName =
    mode === "reports"
      ? "w-full h-full relative z-0 overflow-hidden bg-card [&_.leaflet-container]:!bg-[var(--leaflet-bg)] [&_.continent-label-marker]:!bg-transparent [&_.continent-label-marker]:!border-0 [&_.continent-label-marker]:!shadow-none [&_.leaflet-tooltip]:!bg-card [&_.leaflet-tooltip]:!backdrop-blur-none [&_.leaflet-tooltip]:!border [&_.leaflet-tooltip]:!border-theme [&_.leaflet-tooltip]:!rounded-xl [&_.leaflet-tooltip]:!shadow-[0_20px_50px_rgba(15,23,42,0.18)] [&_.leaflet-tooltip]:!p-0 [&_.leaflet-tooltip]:!text-foreground [&_.leaflet-tooltip]:overflow-hidden [&_.leaflet-grab]:!cursor-pointer [&_.leaflet-dragging_.leaflet-grab]:!cursor-grabbing"
      : "w-full h-full relative z-0 rounded-[24px] overflow-hidden border border-theme/70 transition-all duration-300 bg-card shadow-[0_18px_50px_rgba(15,23,42,0.16)] [&_.leaflet-container]:!bg-[var(--leaflet-bg)] [&_.continent-label-marker]:!bg-transparent [&_.continent-label-marker]:!border-0 [&_.continent-label-marker]:!shadow-none [&_.leaflet-tooltip]:!bg-card [&_.leaflet-tooltip]:!backdrop-blur-none [&_.leaflet-tooltip]:!border [&_.leaflet-tooltip]:!border-theme [&_.leaflet-tooltip]:!rounded-xl [&_.leaflet-tooltip]:!shadow-[0_20px_50px_rgba(15,23,42,0.18)] [&_.leaflet-tooltip]:!p-0 [&_.leaflet-tooltip]:!text-foreground [&_.leaflet-tooltip]:overflow-hidden [&_.leaflet-grab]:!cursor-pointer [&_.leaflet-dragging_.leaflet-grab]:!cursor-grabbing";

  const showGlobe = enableViewToggle && mapView === "globe";

  if (!L && !showGlobe)
    return (
      <div className="w-full h-full bg-slate-900 animate-pulse rounded-none" />
    );

  return (
    <div className={mapShellClassName} style={mapContainerStyle}>
      {showGlobe ? (
        <CesiumGlobe
          worldCountries={worldCountries}
          indiaBorder={indiaBorder}
          countryData={countryData}
          summaryMarkerGroups={summaryMarkerGroups}
          onCountrySelect={handleGlobeCountrySelect}
        />
      ) : (
        <>
          <MapContainer
            center={initialCenter}
            zoom={initialZoom}
            minZoom={minZoomOverride}
            maxZoom={12}
            style={{ height: "100%", width: "100%", background: "transparent" }}
            zoomControl={false}
            attributionControl={false}
            keyboard={false}
            worldCopyJump={true}
            preferCanvas={true}
            maxBounds={[
              [-90, -180],
              [90, 180],
            ]}
            maxBoundsViscosity={1.0}
          >
        <MapResetControl L={L} center={initialCenter} zoom={initialZoom} />
        <EnsureTopPane />

        {worldCountries && worldRenderer && (
          <GeoJSON
            key={`world-${mode}-${countryData.length}`}
            data={worldCountries}
            renderer={worldRenderer}
            pane="geoPane"
            eventHandlers={{
              mousemove: (event) => {
                if (mode !== "summary") return;
                const properties =
                  event.layer?.feature?.properties ||
                  event.target?.feature?.properties ||
                  {};
                const country = getCountryDataForFeature(
                  properties,
                  countryData,
                );
                const name =
                  country?.name ||
                  getFeatureNameCandidates(properties)[0] ||
                  "Unknown";
                setHoveredCountry({
                  name: getMappedCountryName(name),
                  x: event.containerPoint?.x ?? 0,
                  y: event.containerPoint?.y ?? 0,
                });
              },
              mouseout: () => setHoveredCountry(null),
              click: (event) => {
                if (mode !== "summary") return;
                handleFlatCountrySelect(
                  event.layer?.feature?.properties ||
                    event.target?.feature?.properties ||
                    {},
                );
              },
            }}
            style={(feature) => {
              const props =
                feature && feature.properties ? feature.properties : {};
              const isIndia =
                (props.iso_a3 || props.ISO_A3 || props.adm0_a3 || "")
                  .toString()
                  .toUpperCase() === "IND";
              const fillColor =
                mode === "summary"
                  ? getCountryMarkerColor(
                      props,
                      countryData,
                      summaryMarkerGroups,
                    ) || getCountryColor(props)
                  : SUMMARY_LAND_FILL;

              return {
                ...getSummaryLandStyle(),
                ...(isIndia ? { weight: 0 } : {}),
                fillColor,
              };
            }}
          />
        )}

        <ContinentLabels
          L={L}
          labels={CONTINENT_LABELS}
          zoomLevel={zoomLevel}
        />
        <MapZoomListener setZoomLevel={setZoomLevel} />
        <MapViewportListener setViewport={setViewport} />
        <PcapDrillDownController
          focusRequest={pcapDrillDownRequest}
          mode={mode}
        />

        {/* The custom boundary shape covers the coarse Pakistan-side line and
            redraws India's precise outline in the standard country-border style. */}
        {indiaBorder && indiaBoundaryRenderer && (
          <GeoJSON
            key={`india-border-${mode}`}
            data={indiaBorder}
            renderer={indiaBoundaryRenderer}
            pane="indiaPane"
            eventHandlers={{
              mousemove: (event) => {
                if (mode !== "summary") return;
                setHoveredCountry({
                  name: getMappedCountryName("India"),
                  x: event.containerPoint?.x ?? 0,
                  y: event.containerPoint?.y ?? 0,
                });
              },
              mouseout: () => setHoveredCountry(null),
              click: () => {
                if (mode === "summary") {
                  handleFlatCountrySelect({ ADMIN: "India" }, "India");
                }
              },
            }}
            style={() =>
              getIndiaBoundaryStyle(
                mode === "summary"
                  ? getCountryMarkerColor(
                      { ADMIN: "India" },
                      countryData,
                      summaryMarkerGroups,
                    ) || INDIA_LAND_COLOR
                  : SUMMARY_LAND_FILL,
              )
            }
          />
        )}

        {mode === "pcap" &&
          pcapLinePoints.map((point) => {
            const pointStyle = getPcapPointStyle(point.count);
            const lineStyle = getPcapLineStyle(point.count, zoomLevel);
            const positions = [DELHI_COORDS, [point.lat, point.lng]];

            return (
              <Fragment key={`line-${point.id}`}>
                <Polyline
                  pane="topPane"
                  positions={positions}
                  interactive={false}
                  pathOptions={{
                    color: "#0f172a",
                    weight: lineStyle.trackWeight,
                    opacity: lineStyle.trackOpacity,
                    lineCap: "round",
                    lineJoin: "round",
                  }}
                />
                <Polyline
                  pane="topPane"
                  positions={positions}
                  interactive={false}
                  pathOptions={{
                    color: pointStyle.line,
                    weight: lineStyle.weight,
                    opacity: lineStyle.opacity,
                    lineCap: "round",
                    lineJoin: "round",
                  }}
                />
              </Fragment>
            );
          })}

        {mode === "reports"
          ? reportsGroupedPoints.map((point, idx) => {
              const markerSize = point.count > 999 ? 22 : 18;
              const markerFontSize = point.count > 999 ? 8 : 9;
              const icon = L.divIcon({
                html: `
                <div class="reports-map-marker" style="width: ${markerSize}px; height: ${markerSize}px;">
                  <span style="position: relative; z-index: 2; font-size: ${markerFontSize}px;">${point.count.toLocaleString()}</span>
                </div>
              `,
                className: "",
                iconSize: [markerSize, markerSize],
                iconAnchor: [markerSize / 2, markerSize / 2],
              });

              return (
                <Marker
                  pane="topPane"
                  key={idx}
                  position={[point.lat, point.lng]}
                  icon={icon}
                  eventHandlers={{
                    click: () =>
                      setSelectedGroup({
                        lat: point.lat,
                        lng: point.lng,
                        city:
                          point.count === 1
                            ? point.city
                            : `${point.count.toLocaleString()} IPs`,
                        country: point.country,
                        categoryLabel: point.categoryLabel,
                        ips: point.ips,
                        count: point.count,
                        totalPackets: point.totalPackets,
                      }),
                  }}
                >
                  <Tooltip
                    direction="top"
                    offset={[0, -markerSize / 2]}
                    opacity={1}
                  >
                    <div className="p-2 text-[11px] font-bold bg-card text-foreground rounded-lg shadow-xl border border-theme">
                      <div className="text-blue-600 uppercase tracking-tighter mb-1 border-b border-theme pb-1">
                        {point.count === 1
                          ? point.city || "Unknown"
                          : `${point.count.toLocaleString()} IPs`}
                      </div>
                      <div className="flex flex-col gap-1">
                        {point.count === 1 && (
                          <div className="flex justify-between gap-4">
                            <span className="text-slate-500 font-black text-[9px]">
                              IP:
                            </span>
                            <span className="text-foreground text-[9px]">
                              {point.ips[0].ip}
                            </span>
                          </div>
                        )}
                        <div className="flex justify-between gap-4">
                          <span className="text-slate-500 font-black text-[9px]">
                            Located IPs:
                          </span>
                          <span className="text-foreground text-[9px]">
                            {point.count.toLocaleString()}
                          </span>
                        </div>
                        {showPacketCounts && (
                          <div className="flex justify-between gap-4">
                            <span className="text-slate-500 font-black text-[9px]">
                              Packets:
                            </span>
                            <span className="text-foreground text-[9px]">
                              {point.hasPacketCount
                                ? point.totalPackets.toLocaleString()
                                : "—"}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </Tooltip>
                </Marker>
              );
            })
          : mode === "pcap"
            ? pcapMarkerItems.map(({ point, markerSize, icon }) => {
                return (
                  <Marker
                    pane="topPane"
                    key={point.id}
                    position={[point.lat, point.lng]}
                    icon={icon}
                    eventHandlers={{
                      click: () => {
                        /*
                         * A real exact-coordinate group should ALWAYS open
                         * its IP card directly, even when it contains multiple
                         * IPs. This is important for cases such as 5 IPs at the
                         * exact same latitude/longitude.
                         *
                         * A count > 1 that is NOT an exact-coordinate group is
                         * only a temporary screen cluster. Those points are
                         * nearby, not the same location, so clicking it drills
                         * down instead of combining them into one details card.
                         */
                        const isExactGroup =
                          point.isExactCoordinateGroup === true;

                        if (
                          point.count > 1 &&
                          !isExactGroup &&
                          zoomLevel < 12
                        ) {
                          setSelectedGroup(null);
                          setPcapDrillDownRequest({
                            lat: point.lat,
                            lng: point.lng,
                            requestId: `${point.id}-${Date.now()}`,
                          });
                          return;
                        }

                        setSelectedGroup({
                          lat: point.lat,
                          lng: point.lng,
                          city:
                            point.count === 1
                              ? point.city
                              : `${point.count.toLocaleString()} IPs`,
                          country: point.country,
                          ips: point.ips,
                          count: point.count,
                          totalPackets: point.totalPackets,
                        });
                      },
                    }}
                  >
                    <Tooltip
                      direction="top"
                      offset={[0, -markerSize / 2]}
                      opacity={1}
                    >
                      <div className="p-2 text-[11px] font-bold bg-card text-foreground rounded-lg shadow-xl border border-theme">
                        <div className="text-blue-600 uppercase tracking-tighter mb-1 border-b border-theme pb-1">
                          {point.count === 1
                            ? point.city || "Unknown"
                            : `${point.count.toLocaleString()} IPs`}
                        </div>
                        <div className="flex flex-col gap-1">
                          {point.count === 1 && (
                            <div className="flex justify-between gap-4">
                              <span className="text-slate-500 font-black text-[9px]">
                                IP:
                              </span>
                              <span className="text-foreground text-[9px]">
                                {point.ips[0].ip}
                              </span>
                            </div>
                          )}
                          <div className="flex justify-between gap-4">
                            <span className="text-slate-500 font-black text-[9px]">
                              Located IPs:
                            </span>
                            <span className="text-foreground text-[9px]">
                              {point.count.toLocaleString()}
                            </span>
                          </div>
                          <div className="flex justify-between gap-4">
                            <span className="text-slate-500 font-black text-[9px]">
                              Packets:
                            </span>
                            <span className="text-foreground text-[9px]">
                              {point.totalPackets.toLocaleString()}
                            </span>
                          </div>
                        </div>
                      </div>
                    </Tooltip>
                  </Marker>
                );
              })
            : null}

        {mode === "pcap" && L && (
          <Marker
            pane="topPane"
            key="center-delhi"
            position={DELHI_COORDS}
            icon={L.divIcon({
              html: `<div class="${CENTER_DOT_CLASSES}"></div>`,
              className: "",
              iconSize: [12, 12],
              iconAnchor: [6, 6],
            })}
            interactive={false}
          />
        )}
          </MapContainer>

          {mode === "summary" && hoveredCountry && (
            <div
              className="pointer-events-none absolute z-[1100] max-w-[min(15rem,calc(100%-1rem))] truncate rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-bold text-slate-900 shadow-xl"
              style={{
                left: hoveredCountry.x + 14,
                top: hoveredCountry.y + 14,
              }}
            >
              {hoveredCountry.name}
            </div>
          )}

          <div className="map-atmosphere-vignette" aria-hidden="true" />
        </>
      )}

      {title && (
        <div className="absolute top-6 left-6 z-[1000] flex flex-col gap-2 pointer-events-none">
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.96 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ duration: 0.35, ease: "easeOut" }}
            className="group bg-card border border-theme pl-2.5 pr-4 py-2 rounded-2xl shadow-[0_10px_28px_rgba(15,23,42,0.22)] flex items-center gap-2.5 pointer-events-auto transition-transform duration-300 hover:scale-[1.03]"
          >
            <div className="p-2 bg-blue-500/12 rounded-xl flex items-center justify-center transition-transform duration-300 group-hover:scale-110">
              <MapPin size={15} className="text-blue-600" />
            </div>
            <div className="text-[13px] font-black text-foreground tracking-tight leading-none">
              {title}
            </div>
          </motion.div>
        </div>
      )}

      {mode === "summary" && !showGlobe && (
        <div
          className="absolute bottom-5 right-16 z-[1000] w-44 rounded-lg border border-slate-200 bg-white/95 px-3 py-2 shadow-lg backdrop-blur sm:right-20 sm:w-52"
          aria-label="Country IP count groups"
        >
          <div className="mb-1.5 text-[10px] font-semibold text-slate-600 sm:text-xs">
            Country IP counts
          </div>
          <div className="flex flex-col gap-1">
            {summaryMarkerGroups.map((group) => (
              <div
                key={group.id}
                className="flex items-center gap-2 text-[9px] text-slate-600 sm:text-[10px]"
              >
                <span
                  className="h-2.5 w-2.5 shrink-0 rounded-sm"
                  style={{ backgroundColor: group.color }}
                  aria-hidden="true"
                />
                <span>{group.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="absolute top-6 right-6 z-[1000] flex flex-col gap-2">
        <motion.div
          initial={{ opacity: 0, y: -8, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.35, ease: "easeOut" }}
          whileHover={{ scale: 1.03 }}
          className="group bg-card border border-theme pl-2.5 pr-4 py-2 rounded-2xl shadow-[0_10px_28px_rgba(15,23,42,0.22)] flex items-center gap-2.5"
        >
          <div className="p-2 bg-blue-500/12 rounded-xl flex items-center justify-center transition-transform duration-300 group-hover:scale-110">
            <MapPin size={15} className="text-blue-600" />
          </div>
          <div>
            <div className="font-black text-[9px] uppercase tracking-wider text-slate-500 leading-none mb-1">
              {mode === "summary" ? "Total Countries" : "Total IPs Located"}
            </div>
            <div className="text-lg font-black text-foreground tracking-tight leading-none">
              {mode === "summary"
                ? countryData.length
                : validIps.length.toLocaleString()}
            </div>
          </div>
        </motion.div>
      </div>

      {enableViewToggle && mode === "summary" && (
        <div
          className="absolute bottom-5 left-5 z-[1000] inline-flex rounded-xl border border-slate-200 bg-white/95 p-1 shadow-lg backdrop-blur"
          role="group"
          aria-label="Map view"
        >
          <button
            type="button"
            onClick={() => setMapView("flat")}
            aria-pressed={mapView === "flat"}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-bold transition-colors ${
              mapView === "flat"
                ? "bg-blue-600 text-white"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            <MapIcon size={15} />
            Flat 2D
          </button>
          <button
            type="button"
            onClick={() => setMapView("globe")}
            aria-pressed={mapView === "globe"}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-bold transition-colors ${
              mapView === "globe"
                ? "bg-blue-600 text-white"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            <Globe size={15} />
            3D Globe
          </button>
        </div>
      )}

      <AnimatePresence>
        {selectedGroup && (
          <motion.div
            drag
            dragMomentum={false}
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="absolute top-32 right-10 z-[1001] w-96 bg-card border border-theme rounded-2xl shadow-[0_20px_50px_rgba(15,23,42,0.22)] overflow-hidden"
          >
            <motion.div className="p-5 bg-card border-b border-theme flex items-center justify-between cursor-move group/header">
              <div className="flex items-center gap-4">
                <div className="p-2.5 bg-blue-500/10 rounded-xl group-hover/header:scale-110 transition-transform duration-500">
                  <MapPin
                    size={20}
                    className="text-blue-500 drop-shadow-[0_0_8px_rgba(59,130,246,0.4)]"
                  />
                </div>
                <div>
                  <h4 className="text-[15px] font-black text-foreground uppercase ">
                    {selectedGroup.city}
                  </h4>
                  <p className="text-[10px] text-slate-500 font-black uppercase ">
                    {selectedGroup.categoryLabel || selectedGroup.country}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedGroup(null)}
                className="p-2 hover:bg-rose-500/10 hover:text-rose-500 rounded-full transition-colors text-slate-500 group/close"
              >
                <X
                  size={20}
                  className="group-hover/close:rotate-90 transition-transform"
                />
              </button>
            </motion.div>
            <div
              className="max-h-[420px] overflow-y-auto custom-scrollbar p-2 bg-card"
              onPointerDown={(e) => e.stopPropagation()}
            >
              <div className="px-3 py-2 text-[10px] font-black uppercase tracking-wider text-slate-500 border-b border-theme">
                {selectedGroup.ips.length} IP
                {selectedGroup.ips.length !== 1 ? "s" : ""} in this region
              </div>
              <table className="w-full text-left border-separate border-spacing-y-1">
                <thead className="sticky top-0 bg-card z-10">
                  <tr>
                    <th className="px-3 py-2 text-[11px] font-black text-slate-500 ">
                      IP Address
                    </th>
                    {showPacketCounts && (
                      <th className="px-3 py-2 text-[11px] font-black text-slate-500 text-right">
                        Packets
                      </th>
                    )}
                    <th className="w-10"></th>
                  </tr>
                </thead>
                <tbody className="">
                  {selectedGroup.ips.map((ip, i) => (
                    <tr
                      key={i}
                      className="group hover:bg-blue-500/5 transition-colors"
                    >
                      <td className="px-3 py-2.5 font-bold text-[11px] text-foreground">
                        {ip.ip}
                      </td>
                      {showPacketCounts && (
                        <td className="px-3 py-2.5 text-right font-black text-[10px] text-blue-500">
                          {ip.packet_count != null || ip.packets != null
                            ? Number(
                                ip.packet_count ?? ip.packets,
                              ).toLocaleString()
                            : "—"}
                        </td>
                      )}
                      <td className="px-3 py-2.5 text-right">
                        <button
                          onClick={() => onIpClick?.(ip.ip)}
                          className="p-1.5 rounded-lg transition-all text-slate-500 hover:text-blue-600 hover:cursor-pointer"
                        >
                          <Search size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {selectedCountry &&
          (() => {
            const accent = {
              marker: "#3b82f6",
              halo: "rgba(59, 130, 246, 0.35)",
              shadow: "rgba(37, 99, 235, 0.4)",
            };
            return (
              <motion.div
                drag
                dragMomentum={false}
                initial={{ opacity: 0, scale: 0.94, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.94, y: 20 }}
                className="absolute top-28 right-10 z-[1001] w-[320px] bg-card border border-theme rounded-2xl overflow-hidden cursor-move"
                style={{
                  boxShadow: `0 0 0 1px ${accent.halo}, 0 0 40px 4px ${accent.halo}, 0 20px 40px -14px rgba(0,0,0,0.4)`,
                }}
              >
                <div
                  className="h-[3px] w-full"
                  style={{
                    background: `linear-gradient(90deg, ${accent.marker}, transparent)`,
                  }}
                />
                <div className="p-5">
                  <div className="flex items-center justify-between mb-5">
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className="relative shrink-0 rounded-lg overflow-hidden flex items-center justify-center"
                        style={{
                          boxShadow: `0 0 0 1px ${accent.halo}, 0 4px 12px ${accent.shadow}`,
                        }}
                      >
                        <CountryFlag iso2={selectedCountry.iso2} size={30} />
                      </div>
                      <div className="min-w-0">
                        <h4 className="text-base font-black text-foreground uppercase tracking-tight leading-tight truncate">
                          {selectedCountry.name}
                        </h4>
                        {/* <p className="text-[9px] text-slate-500 font-bold uppercase tracking-widest">Regional Intelligence</p> */}
                      </div>
                    </div>
                    <button
                      onPointerDown={(e) => e.stopPropagation()}
                      onClick={() => setSelectedCountry(null)}
                      className="p-1.5 hover:bg-rose-500/10 hover:text-rose-500 rounded-full transition-colors text-slate-500 shrink-0"
                    >
                      <X size={16} />
                    </button>
                  </div>

                  <div className="space-y-2">
                    <div
                      className="flex items-center justify-between px-4 py-3 bg-slate-500/5 rounded-xl border-l-2"
                      style={{ borderColor: accent.marker }}
                    >
                      <div className="flex items-center gap-2.5">
                        <Radio size={14} style={{ color: accent.marker }} />
                        <div className="text-[10px] font-black uppercase tracking-wide text-slate-500">
                          Total IP count
                        </div>
                      </div>
                      <div
                        className="text-lg font-black"
                        style={{ color: accent.marker }}
                      >
                        {(selectedCountry.count || 0).toLocaleString()}
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-500/5 rounded-xl border-l-2 border-slate-500/20">
                      <div className="flex items-center gap-2.5">
                        <Activity size={14} className="text-slate-500" />
                        <div className="text-[10px] font-black uppercase tracking-wide text-slate-500">
                          Captures seen
                        </div>
                      </div>
                      <div className="text-lg font-black text-foreground">
                        {(selectedCountry.captures || 0).toLocaleString()}
                      </div>
                    </div>
                    <div className="flex items-center justify-between px-4 py-3 bg-slate-500/5 rounded-xl border-l-2 border-slate-500/20">
                      <div className="flex items-center gap-2.5">
                        <Zap size={14} className="text-slate-500" />
                        <div className="text-[10px] font-black uppercase tracking-wide text-slate-500">
                          Packet volume
                        </div>
                      </div>
                      <div className="text-lg font-black text-foreground">
                        {(selectedCountry.packets || 0).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>
            );
          })()}
      </AnimatePresence>

      {/*
        Only the pieces that Tailwind utility classes genuinely cannot express are left here:
        - @keyframes definitions (Tailwind's arbitrary `animate-[...]` values need the keyframes
          to exist somewhere in the stylesheet; they can't be authored as utility classes).
        - The custom scrollbar's ::-webkit-scrollbar pseudo-elements (no core Tailwind utility
          covers these without an extra plugin).
        Everything else that used to live in this block (marker colors, borders, shadows,
        hover states, leaflet-tooltip/leaflet-container/leaflet-grab theming, continent
        label styling, etc.) has been moved into Tailwind classes above.
      */}
      <style jsx global>{`
        .custom-dot-marker {
          background: #3b82f6;
          border: 2px solid white;
          border-radius: 50%;
          box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
          transition: all 0.2s ease-out;
          cursor: pointer;
        }
        .custom-dot-marker:hover {
          transform: scale(3) !important;
          background: #ffffff !important;
          box-shadow:
            0 0 40px rgba(37, 99, 235, 1),
            0 0 80px rgba(37, 99, 235, 0.4);
          z-index: 1000 !important;
          border: 2.5px solid #2563eb;
        }
        .center-red-dot {
          width: 12px;
          height: 12px;
          background: #ef4444;
          border-radius: 50%;
          border: 2px solid white;
          box-shadow: 0 6px 18px rgba(239, 68, 68, 0.28);
        }
        .continent-label-marker {
          background: transparent !important;
          border: 0 !important;
          box-shadow: none !important;
        }
        .continent-label {
          transform: translate(-50%, -50%);
          white-space: pre-line;
          text-align: center;
          font-weight: 800;
          letter-spacing: 0.06em;
          line-height: 1.05;
          text-transform: uppercase;
          user-select: none;
          pointer-events: none;
          color: ${
            mode === "summary"
              ? "rgba(15, 23, 42, 0.78)"
              : "rgba(30, 41, 59, 0.68)"
          };
          text-shadow: ${
            mode === "summary"
              ? "0 1px 2px rgba(255,255,255,0.6), 0 0 10px rgba(255,255,255,0.4)"
              : "0 1px 2px rgba(255,255,255,0.7), 0 0 10px rgba(255,255,255,0.4)"
          };
        }
        .continent-label.label-large {
          font-size: 13.5px;
        }
        .continent-label.label-medium {
          font-size: 11px;
          line-height: 1.02;
        }
        .pcap-marker {
          background: #3b82f6;
          border: 2px solid white;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          color: white;
          font-weight: 900;
          font-size: 8px;
          text-shadow: 0 1px 2px rgba(15, 23, 42, 0.25);
          transition:
            transform 0.25s cubic-bezier(0.2, 0.9, 0.2, 1),
            box-shadow 0.25s ease;
          cursor: pointer;
          position: relative;
          will-change: transform;
        }
        .reports-map-marker {
          background: ${REPORT_MARKER_COLORS.fill};
          border: 1.5px solid #ffffff;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          color: #ffffff;
          font-weight: 900;
          text-shadow: 0 1px 2px rgba(15, 23, 42, 0.28);
          box-shadow: 0 1px 5px ${REPORT_MARKER_COLORS.shadow};
          transition:
            transform 0.18s ease,
            box-shadow 0.18s ease;
          cursor: pointer;
        }
        .reports-map-marker:hover {
          transform: translateY(-2px) scale(1.08);
          box-shadow: 0 3px 9px ${REPORT_MARKER_COLORS.hoverShadow};
          z-index: 1000;
        }
        .pcap-marker-sprinkle {
          animation: pcap-marker-sprinkle 460ms
            cubic-bezier(0.16, 1.15, 0.28, 1) both;
        }
        .pcap-marker-focus {
          border-width: 2.5px;
          box-shadow:
            0 0 0 5px rgba(37, 99, 235, 0.12),
            0 8px 18px rgba(30, 64, 175, 0.22) !important;
        }
        .pcap-marker:hover {
          transform: translateY(-6px) scale(1.16) !important;
          box-shadow:
            0 0 0 8px rgba(59, 130, 246, 0.18),
            0 14px 26px rgba(37, 99, 235, 0.32) !important;
          z-index: 1000 !important;
        }
        .pcap-pulse {
          position: absolute;
          width: 100%;
          height: 100%;
          border-radius: 50%;
          background: #3b82f6;
          opacity: 0.4;
          animation: pcap-map-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
          pointer-events: none;
          z-index: 1;
        }
        .pcap-sprinkle-ring {
          position: absolute;
          width: 100%;
          height: 100%;
          border-radius: 50%;
          opacity: 0;
          pointer-events: none;
          z-index: 1;
          animation: pcap-sprinkle-ring 520ms ease-out both;
        }
        @keyframes pcap-map-pulse {
          0% {
            transform: scale(1);
            opacity: 0.4;
          }
          100% {
            transform: scale(2.5);
            opacity: 0;
          }
        }
        @keyframes pcap-marker-sprinkle {
          0% {
            opacity: 0;
            transform: translate(var(--sprinkle-x), var(--sprinkle-y))
              scale(0.32);
          }
          58% {
            opacity: 1;
            transform: translate(
                calc(var(--sprinkle-x) * -0.14),
                calc(var(--sprinkle-y) * -0.14)
              )
              scale(1.16);
          }
          78% {
            transform: translate(
                calc(var(--sprinkle-x) * 0.06),
                calc(var(--sprinkle-y) * 0.06)
              )
              scale(0.96);
          }
          100% {
            opacity: 1;
            transform: translate(0, 0) scale(1);
          }
        }
        @keyframes pcap-sprinkle-ring {
          0% {
            opacity: 0.34;
            transform: scale(0.5);
          }
          100% {
            opacity: 0;
            transform: scale(2.1);
          }
        }
        .leaflet-bottom.leaflet-right {
          right: 12px !important;
          bottom: 12px !important;
        }

        .map-controls-stack {
          margin: 0 !important;
          padding: 0 !important;
          border: 0 !important;
          border-radius: 10px !important;
          overflow: hidden;
          box-shadow: 0 6px 18px rgba(15, 23, 42, 0.16) !important;
        }

        .map-controls-stack .map-control-button {
          width: 34px !important;
          height: 34px !important;
          line-height: 34px !important;

          display: flex !important;
          align-items: center !important;
          justify-content: center !important;

          margin: 0 !important;
          padding: 0 !important;

          border: 0 !important;
          border-bottom: 1px solid hsl(var(--border) / 0.7) !important;

          background: hsl(var(--card)) !important;
          color: hsl(var(--foreground)) !important;

          text-decoration: none !important;
          font-weight: 700 !important;

          transition: none !important;
        }

        .map-controls-stack .map-control-button:last-child {
          border-bottom: 0 !important;
        }

        .map-controls-stack .map-control-button:hover,
        .map-controls-stack .map-control-button:active,
        .map-controls-stack .map-control-button:focus,
        .map-controls-stack .map-control-button:focus-visible,
        .map-controls-stack .map-control-button:visited {
          background: hsl(var(--card)) !important;
          color: hsl(var(--foreground)) !important;
          outline: none !important;
          box-shadow: none !important;
        }

        .map-controls-stack .map-control-button:nth-child(1),
        .map-controls-stack .map-control-button:nth-child(2) {
          font-size: 18px !important;
          font-weight: 600 !important;
        }

        .map-controls-stack .map-reset-button svg {
          width: 16px !important;
          height: 16px !important;
          display: block !important;
        }

        .leaflet-container {
          background: ${SUMMARY_MAP_BACKGROUND} !important;
        }
        .map-atmosphere-vignette {
          position: absolute;
          inset: 0;
          z-index: 450;
          pointer-events: none;
          background: radial-gradient(
            120% 100% at 50% 42%,
            transparent 65%,
            rgba(10, 30, 60, 0.16) 100%
          );
        }
        .leaflet-tooltip {
          background: hsl(var(--card)) !important;
          backdrop-filter: none !important;
          border: 1px solid hsl(var(--border)) !important;
          border-radius: 12px !important;
          box-shadow:
            0 20px 25px -5px rgb(0 0 0 / 0.1),
            0 8px 10px -6px rgb(0 0 0 / 0.1) !important;
          padding: 0 !important;
          color: hsl(var(--foreground)) !important;
          overflow: hidden;
        }
        .leaflet-grab {
          cursor: pointer !important;
        }
        .leaflet-dragging .leaflet-grab {
          cursor: grabbing !important;
        }
        .leaflet-interactive:focus,
        .leaflet-interactive:focus-visible,
        .leaflet-container svg:focus,
        .leaflet-container path:focus {
          outline: none !important;
        }
        .custom-scrollbar::-webkit-scrollbar {
          width: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: hsl(var(--border) / 0.5);
          border-radius: 10px;
        }
      `}</style>
    </div>
  );
}

MapZoomListener.propTypes = {
  setZoomLevel: PropTypes.func,
};

MapViewportListener.propTypes = {
  setViewport: PropTypes.func,
};

PcapDrillDownController.propTypes = {
  focusRequest: PropTypes.object,
  mode: PropTypes.string,
};

MapResetControl.propTypes = {
  L: PropTypes.object,
  center: PropTypes.arrayOf(PropTypes.number),
  zoom: PropTypes.number,
};

ContinentLabels.propTypes = {
  L: PropTypes.object,
  labels: PropTypes.array,
  zoomLevel: PropTypes.number,
};

WorldMapLeaflet.propTypes = {
  externalIps: PropTypes.array,
  onIpClick: PropTypes.func,
  mode: PropTypes.string,
  countryData: PropTypes.array,
  title: PropTypes.string,
  fallbackCountry: PropTypes.string,
  reportLabel: PropTypes.string,
  reportType: PropTypes.string,
  enableViewToggle: PropTypes.bool,
  initialZoomOverride: PropTypes.number,
  minZoomOverride: PropTypes.number,
  showPacketCounts: PropTypes.bool,
};
