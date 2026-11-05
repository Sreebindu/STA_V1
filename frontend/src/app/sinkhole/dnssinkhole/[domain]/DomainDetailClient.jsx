"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  ArrowUpRight,
  CalendarDays,
  Maximize2,
  FileText,
  Globe,
  MapPin,
  Network,
  Search,
  Server,
  X,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { WorldMapLeaflet } from "@/app/dashboard/WorldMapLeaflet";
import { fetchGlobalMapData } from "@/app/dashboard/dashboardApiService";
import {
  getCountryDisplayName,
  getCountryFlagClass,
} from "@/app/dashboard/countryUtils";

const EMPTY_ARRAY = [];
const DNS_SINKHOLE_ID = 2;

const formatNumber = (value) => Number(value || 0).toLocaleString();

const formatTimestamp = (value) => {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
};

const dateValue = (value) => {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toISOString().slice(0, 10);
};

const hasCoordinates = (item) => {
  if (
    item?.latitude == null ||
    item?.longitude == null ||
    item.latitude === "" ||
    item.longitude === ""
  ) {
    return false;
  }
  const latitude = Number(item.latitude);
  const longitude = Number(item.longitude);
  return (
    Number.isFinite(latitude) &&
    Number.isFinite(longitude) &&
    latitude >= -90 &&
    latitude <= 90 &&
    longitude >= -180 &&
    longitude <= 180
  );
};

function MetricCard({ label, value, detail, icon: Icon, accent }) {
  return (
    <article className="rounded-2xl border border-blue-100 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-xs font-medium uppercase ">
            {label}
          </p>
          <p className="mt-2 text-2xl font-bold tabular-nums text-slate-900">
            {formatNumber(value)}
          </p>
          <p className="mt-1 text-xs ">{detail}</p>
        </div>
        <span
          className={`flex h-10 w-10 items-center justify-center rounded-xl ${accent}`}
        >
          <Icon size={28} />
        </span>
      </div>
    </article>
  );
}

export default function DomainDetailClient({
  selectedDomain,
  domainDetails,
}) {
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [ipSearch, setIpSearch] = useState("");
  const [ispSearch, setIspSearch] = useState("");
  const [selectedTime, setSelectedTime] = useState(null);
  const [selectedIpDomains, setSelectedIpDomains] = useState(null);
  const [selectedIpPcaps, setSelectedIpPcaps] = useState(null);
  const [isMapExpanded, setIsMapExpanded] = useState(false);
  const [mapData, setMapData] = useState(EMPTY_ARRAY);
  const [mapError, setMapError] = useState("");

  const timeline = domainDetails?.timeline ?? EMPTY_ARRAY;
  const domainIps = domainDetails?.ips ?? EMPTY_ARRAY;
  const requestRecords = domainDetails?.request_records ?? EMPTY_ARRAY;

  const enrichedIps = useMemo(() => {
    const mapByIp = new Map(mapData.map((item) => [item.ip, item]));
    return domainIps.map((item) => {
      const location = mapByIp.get(item.ip);
      return {
        ...location,
        ...item,
        latitude: item.latitude ?? location?.latitude,
        longitude: item.longitude ?? location?.longitude,
        country: item.country ?? location?.country,
        city: item.city ?? location?.city,
      };
    });
  }, [domainIps, mapData]);

  const selectedTimeIps = useMemo(() => {
    if (!selectedTime) return EMPTY_ARRAY;
    const ipsByAddress = new Map(enrichedIps.map((item) => [item.ip, item]));
    return (selectedTime.ips ?? []).map(
      (ip) =>
        ipsByAddress.get(ip) ?? {
          ip,
          isp: "Unknown",
          domain_count: 0,
          pcap_ids: EMPTY_ARRAY,
        },
    );
  }, [selectedTime, enrichedIps]);

  const filteredTimeline = useMemo(
    () =>
      timeline.filter((point) => {
        if (!point.timestamp) return !startDate && !endDate;
        const day = dateValue(point.timestamp);
        return (!startDate || day >= startDate) && (!endDate || day <= endDate);
      }),
    [timeline, startDate, endDate],
  );

  const filteredIps = useMemo(
    () =>
      enrichedIps.filter((item) => {
        const hasDateFilter = Boolean(startDate || endDate);
        const inRange = !hasDateFilter
          ? true
          : (item.timestamps ?? []).some((timestamp) => {
              const day = dateValue(timestamp);
              return (
                day &&
                (!startDate || day >= startDate) &&
                (!endDate || day <= endDate)
              );
            });
        return (
          inRange &&
          item.ip?.toLowerCase().includes(ipSearch.trim().toLowerCase()) &&
          (item.isp || "Unknown")
            .toLowerCase()
            .includes(ispSearch.trim().toLowerCase())
        );
      }),
    [enrichedIps, startDate, endDate, ipSearch, ispSearch],
  );

  const hasDateFilter = Boolean(startDate || endDate);
  const totalRequests = hasDateFilter
    ? requestRecords.reduce((total, record) => {
        const isInRange = (record.timestamps ?? []).some((timestamp) => {
          const day = dateValue(timestamp);
          return (
            day &&
            (!startDate || day >= startDate) &&
            (!endDate || day <= endDate)
          );
        });
        return total + (isInRange ? Number(record.request_count || 0) : 0);
      }, 0)
    : Number(domainDetails?.request_count ?? selectedDomain.request_count ?? 0);
  const connectedIpsInRange =
    startDate || endDate
      ? new Set(filteredTimeline.flatMap((point) => point.ips ?? [])).size
      : domainIps.length;
  const pcapCount = new Set(
    filteredTimeline.flatMap((point) => point.pcap_ids ?? []),
  ).size;
  const ispCount = new Set(filteredIps.map((item) => item.isp || "Unknown")).size;

  const mapIps = filteredIps.filter(hasCoordinates);

  useEffect(() => {
    let cancelled = false;
    fetchGlobalMapData()
      .then((response) => {
        if (!cancelled) {
          setMapData(Array.isArray(response?.data) ? response.data : []);
        }
      })
      .catch((error) => {
        console.error("Could not load map location data:", error);
        if (!cancelled) setMapError("Location enrichment is unavailable.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handleTimelineClick = (state) => {
    const activeIndex = state?.activeTooltipIndex ?? state?.activeIndex;
    const point =
      state?.activePayload?.[0]?.payload ??
      (typeof activeIndex === "number"
        ? filteredTimeline[activeIndex]
        : filteredTimeline.find(
            (item) => item.timestamp === state?.activeLabel,
          ));
    if (point) setSelectedTime(point);
  };

  const clearFilters = () => {
    setStartDate("");
    setEndDate("");
    setIpSearch("");
    setIspSearch("");
    setSelectedTime(null);
  };

  const archiveLink = (ip) =>
    `/dashboard?tab=${encodeURIComponent("IP Search")}&ip=${encodeURIComponent(ip)}`;

  useEffect(() => {
    if (!selectedIpDomains && !selectedIpPcaps) return undefined;
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setSelectedIpDomains(null);
        setSelectedIpPcaps(null);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [selectedIpDomains, selectedIpPcaps]);

  useEffect(() => {
    if (!selectedTime) return undefined;

    const handleKeyDown = (event) => {
      if (event.key === "Escape") setSelectedTime(null);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [selectedTime]);

  useEffect(() => {
    if (!isMapExpanded) return undefined;

    const handleKeyDown = (event) => {
      if (event.key === "Escape") setIsMapExpanded(false);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", handleKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isMapExpanded]);

  const handleMapIpClick = (ip) => {
    setIpSearch(ip);
    setIsMapExpanded(false);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => {
        document
          .getElementById("domain-ip-table")
          ?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  };

  const renderMap = () => (
    <WorldMapLeaflet
      externalIps={mapIps}
      mode="reports"
      initialZoomOverride={1.6}
      minZoomOverride={1}
      showPacketCounts={false}
      onIpClick={handleMapIpClick}
    />
  );

  return (
    <main className="min-h-[calc(100vh-56px)] bg-slate-50/70 px-4 py-5 text-slate-900 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-[1600px] space-y-5">
        <header className="flex flex-col gap-4 rounded-2xl border border-blue-100 bg-[radial-gradient(ellipse_at_top_left,_rgba(219,234,254,0.72),_transparent_52%),linear-gradient(120deg,#ffffff,#f1f7ff)] p-4 shadow-sm xl:flex-row xl:items-center xl:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-blue-500/10 text-blue-600">
              <Globe size={22} />
            </span>
            <div className="min-w-0">
              <h1 className="mt-1 truncate text-xl font-bold tracking-tight text-slate-900 sm:text-2xl">
                {selectedDomain.host}
              </h1>
            </div>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center xl:ml-auto">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-800">
              <CalendarDays size={17} className="text-blue-600" />
              <span>Filter dates</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <label className="flex items-center gap-2 rounded-xl border border-blue-100 bg-white px-3 py-2 text-xs text-slate-500">
                From
                <input
                  aria-label="Start date"
                  type="date"
                  value={startDate}
                  max={endDate || undefined}
                  onChange={(event) => {
                    setStartDate(event.target.value);
                    setSelectedTime(null);
                  }}
                  className="bg-transparent text-sm text-slate-800 outline-none"
                />
              </label>
              <label className="flex items-center gap-2 rounded-xl border border-blue-100 bg-white px-3 py-2 text-xs text-slate-500">
                To
                <input
                  aria-label="End date"
                  type="date"
                  value={endDate}
                  min={startDate || undefined}
                  onChange={(event) => {
                    setEndDate(event.target.value);
                    setSelectedTime(null);
                  }}
                  className="bg-transparent text-sm text-slate-800 outline-none"
                />
              </label>
              {(startDate || endDate || ipSearch || ispSearch) && (
                <button
                  type="button"
                  onClick={clearFilters}
                  className="rounded-xl px-3 py-2 text-sm font-semibold text-blue-700 hover:bg-blue-50"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
          <Link
            href="/sinkhole/dnssinkhole"
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl border border-blue-200 bg-white px-3.5 py-2.5 text-sm font-semibold text-blue-700 transition hover:border-blue-400 hover:bg-blue-50"
          >
            <X size={16} />
            Back to domains
          </Link>
        </header>

        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            label="Requests"
            value={totalRequests}
            detail="Total requests recorded for this domain"
            icon={Activity}
            accent="bg-emerald-500/10 text-emerald-600"
          />
          <MetricCard
            label="Connected IPs"
            value={connectedIpsInRange}
            detail="Unique IPs observed in selected period"
            icon={Network}
            accent="bg-blue-500/10 text-blue-600"
          />
          <MetricCard
            label="PCAPs"
            value={
              pcapCount ||
              (startDate || endDate ? 0 : selectedDomain.pcap_ids?.length)
            }
            detail="Captures represented in the IP results"
            icon={FileText}
            accent="bg-violet-500/10 text-violet-600"
          />
          <MetricCard
            label="ISPs"
            value={ispCount}
            detail="Distinct providers in selected period"
            icon={Server}
            accent="bg-amber-500/10 text-amber-600"
          />
        </section>

        <section className="grid gap-5 xl:grid-cols-[minmax(0,1.35fr)_minmax(380px,0.9fr)]">
          <article className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="font-semibold text-slate-900">
                  Connected IP activity
                </h2>
              </div>
            </div>
            <div className="h-[270px] w-full">
              {filteredTimeline.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={filteredTimeline}
                    margin={{ top: 8, right: 12, bottom: 22, left: 8 }}
                    onClick={handleTimelineClick}
                  >
                    <CartesianGrid stroke="#e2e8f0" strokeDasharray="4 4" />
                    <XAxis
                      dataKey="timestamp"
                      tickFormatter={(value) =>
                        value === "unknown"
                          ? "Unknown"
                          : new Date(value).toLocaleString(undefined, {
                              month: "short",
                              day: "numeric",
                              hour: "2-digit",
                              minute: "2-digit",
                            })
                      }
                      minTickGap={24}
                      tick={{ fill: "#000000", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                      label={{
                        value: "Timestamp",
                        position: "insideBottom",
                        offset: -14,
                        style: {
                          fill: "#000000",
                          fontSize: 11,
                          fontWeight: 500,
                        },
                      }}
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fill: "#000000", fontSize: 11 }}
                      axisLine={false}
                      tickLine={false}
                      label={{
                        value: "Connected IPs",
                        angle: -90,
                        position: "insideLeft",
                        style: {
                          fill: "#000000",
                          fontSize: 11,
                          fontWeight: 500,
                          textAnchor: "middle",
                        },
                      }}
                    />
                    <Tooltip
                      labelFormatter={(value) => formatTimestamp(value)}
                      contentStyle={{
                        backgroundColor: "#ffffff",
                        borderRadius: 12,
                        borderColor: "#dbeafe",
                        color: "#0f172a",
                        boxShadow: "0 8px 24px rgba(15, 23, 42, .12)",
                      }}
                      itemStyle={{ color: "#1d4ed8" }}
                    />
                    <Line
                      type="monotone"
                      dataKey="ip_count"
                      name="IP's Connected "
                      stroke="#2563eb"
                      strokeWidth={2.5}
                      activeDot={{ r: 6, cursor: "pointer" }}
                      dot={{ r: 4, cursor: "pointer" }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-2 rounded-xl border border-dashed border-blue-200 text-center">
                  <Activity size={21} className="text-slate-400" />
                  <p className="text-sm font-medium text-slate-800">
                    No activity for this date range
                  </p>
                  <p className="text-xs text-slate-500">
                    Clear the date filter to see activity across all timestamps.
                  </p>
                </div>
              )}
            </div>
          </article>

          <article className="rounded-2xl border border-blue-100 bg-white p-5 shadow-sm">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div>
                <h2 className="font-semibold text-slate-900">
                  Victim IP Geo Map
                </h2>
              </div>
              <span className="inline-flex items-center gap-1 rounded-lg bg-blue-50 px-2.5 py-1.5 text-xs font-medium text-blue-700">
                <MapPin size={13} />
                {mapIps.length}{" "}
                mapped
              </span>
            </div>
            <div className="relative h-[310px] overflow-hidden rounded-xl border border-blue-100">
              {renderMap()}
              <button
                type="button"
                aria-label="Expand IP map"
                title="Expand map"
                onClick={() => setIsMapExpanded(true)}
                className="absolute right-3 top-3 z-[800] rounded-lg border border-blue-100 bg-white/95 p-2 text-slate-700 shadow-sm transition hover:bg-blue-50 hover:text-blue-700"
              >
                <Maximize2 size={16} />
              </button>
              {mapError && (
                <p className="absolute bottom-2 left-2 right-2 rounded-lg bg-white/95 px-3 py-2 text-xs text-slate-600 shadow">
                  {mapError} The map shows coordinates available in the domain
                  records.
                </p>
              )}
            </div>
          </article>
        </section>

        {isMapExpanded && (
          <div
            className="fixed inset-0 z-[1200] flex items-center justify-center bg-slate-950/70 p-4 backdrop-blur-sm sm:p-8"
            role="presentation"
            onClick={() => setIsMapExpanded(false)}
          >
            <section
              className="relative h-[min(88vh,900px)] w-full max-w-[1500px] overflow-hidden rounded-2xl border border-blue-100 bg-white shadow-2xl"
              role="dialog"
              aria-modal="true"
              aria-label="Expanded IP map"
              onClick={(event) => event.stopPropagation()}
            >
              <header className="absolute inset-x-0 top-0 z-[801] flex items-center justify-between border-b border-blue-100 bg-white/95 px-4 py-3 shadow-sm backdrop-blur">
                <h2 className="text-sm font-semibold text-slate-900">
                  Global IP map · {mapIps.length} mapped
                </h2>
                <button
                  type="button"
                  aria-label="Close expanded map"
                  title="Close map"
                  onClick={() => setIsMapExpanded(false)}
                  className="rounded-lg p-2 text-slate-600 transition hover:bg-slate-100 hover:text-slate-900"
                >
                  <X size={20} />
                </button>
              </header>
              <div className="absolute inset-0 pt-[58px]">{renderMap()}</div>
            </section>
          </div>
        )}

        <section
          id="domain-ip-table"
          className="scroll-mt-20 overflow-hidden rounded-2xl border border-blue-100 bg-white shadow-sm"
        >
          <div className="flex flex-col justify-between gap-4 border-b border-blue-100 p-5 lg:flex-row lg:items-center">
            <div>
                  <h2 className="font-semibold text-slate-900">Connected IPs</h2>
                  <p className="mt-1 text-xs text-slate-500">
                {filteredIps.length.toLocaleString()} of{" "}
                {domainIps.length.toLocaleString()} IP's
              </p>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <label className="relative">
                <Search
                  size={15}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  type="search"
                  value={ipSearch}
                  onChange={(event) => setIpSearch(event.target.value)}
                  placeholder="Search IP address"
                  className="w-full rounded-xl border border-blue-100 bg-white py-2.5 pl-9 pr-3 text-sm text-slate-800 outline-none focus:border-blue-400 sm:w-56"
                />
              </label>
              <label className="relative">
                <Server
                  size={15}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  type="search"
                  value={ispSearch}
                  onChange={(event) => setIspSearch(event.target.value)}
                  placeholder="Search ISP"
                  className="w-full rounded-xl border border-blue-100 bg-white py-2.5 pl-9 pr-3 text-sm text-slate-800 outline-none focus:border-blue-400 sm:w-56"
                />
              </label>
            </div>
          </div>

          <div className="max-h-[480px] overflow-auto">
            <table className="w-full min-w-[900px] text-left">
              <thead className="sticky top-0 z-10 bg-blue-50">
                <tr className="border-b border-blue-100">
                  {[
                    "IP address",
                    "ISP",
                    "Domains",
                    "PCAPs",
                    "Geo",
                    "More info",
                  ].map((heading) => (
                    <th
                      key={heading}
                      className="px-5 py-3 text-[10px] font-semibold uppercase tracking-wider text-blue-800"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredIps.map((item, index) => {
                  const country = item.country
                    ? getCountryDisplayName(item.country)
                    : "Unknown";
                  const countryFlag = item.country
                    ? getCountryFlagClass(item.country)
                    : null;
                  return (
                    <tr
                      key={item.ip}
                      className="transition-colors hover:bg-blue-50/70"
                    >
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-500/10 text-xs font-bold tabular-nums text-blue-700">
                            {String(index + 1).padStart(2, "0")}
                          </span>
                          <Link
                            href={archiveLink(item.ip)}
                            className="font-mono text-sm font-semibold text-blue-700 hover:text-blue-900 hover:underline"
                          >
                            {item.ip}
                          </Link>
                        </div>
                      </td>
                      <td className="max-w-[240px] truncate px-5 py-3.5 text-sm text-slate-700">
                        <span className="inline-flex max-w-full items-center gap-2 rounded-full bg-slate-100 px-2.5 py-1">
                          <Server size={13} className="shrink-0 text-blue-600" />
                          <span className="truncate">{item.isp || "Unknown"}</span>
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-sm tabular-nums text-slate-700">
                        <button
                          type="button"
                          aria-haspopup="dialog"
                          aria-label={`Show domains for ${item.ip}`}
                          onClick={() => setSelectedIpDomains(item)}
                          className="rounded-lg bg-emerald-500/10 px-2.5 py-1 font-semibold text-emerald-700 transition hover:bg-emerald-500/20 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2"
                        >
                          {formatNumber(item.domain_count)}
                        </button>
                      </td>
                      <td className="px-5 py-3.5 text-sm tabular-nums text-slate-700">
                        <button
                          type="button"
                          aria-haspopup="dialog"
                          aria-label={`Show PCAPs for ${item.ip}`}
                          onClick={() => setSelectedIpPcaps(item)}
                          className="rounded-lg bg-violet-500/10 px-2.5 py-1 font-semibold text-violet-700 transition hover:bg-violet-500/20 focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2"
                        >
                          {formatNumber(item.pcap_ids?.length)}
                        </button>
                      </td>
                      <td className="max-w-[240px] truncate px-5 py-3.5 text-sm text-slate-600">
                        <span className="inline-flex items-center gap-2">
                          {countryFlag ? (
                            <span
                              className={`${countryFlag} shrink-0 rounded-sm`}
                              aria-label={`${country} flag`}
                              title={country}
                            />
                          ) : (
                            <MapPin size={14} className="shrink-0 text-slate-400" />
                          )}
                          <span className="truncate">{country}</span>
                        </span>
                      </td>
                      <td className="px-5 py-3.5">
                        <Link
                          href={archiveLink(item.ip)}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 text-xs font-semibold text-blue-700 transition hover:border-blue-400 hover:bg-blue-100 hover:text-blue-900"
                        >
                          More info
                          <ArrowUpRight size={13} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
                {!filteredIps.length && (
                  <tr>
                    <td
                      colSpan={6}
                      className="px-4 py-14 text-center text-sm text-slate-500"
                    >
                      No connected IPs match the selected filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
      {selectedTime && (
        <div
          className="fixed inset-0 z-[1000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
          onClick={() => setSelectedTime(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="timestamp-connected-ips-title"
            className="w-full max-w-4xl rounded-2xl border border-blue-100 bg-white p-5 shadow-2xl sm:p-6"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="mb-5 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h2
                  id="timestamp-connected-ips-title"
                  className="text-lg font-bold text-slate-900"
                >
                  Connected IPs at this time
                </h2>
                <p className="mt-1 text-sm text-slate-500">
                  {formatTimestamp(selectedTime.timestamp)} ·{" "}
                  {selectedTimeIps.length.toLocaleString()} IPs
                </p>
              </div>
              <button
                type="button"
                aria-label="Close timestamp IP table"
                onClick={() => setSelectedTime(null)}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
              >
                <X size={18} />
              </button>
            </header>
            <div className="max-h-[60vh] overflow-auto rounded-xl border border-blue-100">
              <table className="w-full min-w-[760px] text-left">
                <thead className="sticky top-0 z-10 bg-blue-50">
                  <tr className="border-b border-blue-100">
                    {[
                      "IP address",
                      "ISP",
                      "Domains",
                      "PCAPs",
                      "Geo",
                      "More info",
                    ].map((heading) => (
                        <th
                          key={heading}
                          className="px-4 py-3 text-[10px] font-semibold uppercase tracking-wider text-blue-800"
                        >
                          {heading}
                        </th>
                      ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {selectedTimeIps.map((item) => {
                    const country = item.country
                      ? getCountryDisplayName(item.country)
                      : "Unknown";
                    const countryFlag = item.country
                      ? getCountryFlagClass(item.country)
                      : null;
                    return (
                      <tr
                        key={item.ip}
                        className="transition-colors hover:bg-blue-50/70"
                      >
                      <td className="px-4 py-3">
                        <Link
                          href={archiveLink(item.ip)}
                          onClick={() => setSelectedTime(null)}
                          className="font-mono text-sm font-semibold text-blue-700 hover:text-blue-900 hover:underline"
                        >
                          {item.ip}
                        </Link>
                      </td>
                      <td className="max-w-[220px] truncate px-4 py-3 text-sm text-slate-700">
                        {item.isp || "Unknown"}
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums text-slate-700">
                        <button
                          type="button"
                          aria-haspopup="dialog"
                          aria-label={`Show domains for ${item.ip}`}
                          onClick={() => setSelectedIpDomains(item)}
                          className="rounded-lg bg-emerald-500/10 px-2.5 py-1 font-semibold text-emerald-700 transition hover:bg-emerald-500/20 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:ring-offset-2"
                        >
                          {formatNumber(item.domain_count)}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-sm tabular-nums text-slate-700">
                        <button
                          type="button"
                          aria-haspopup="dialog"
                          aria-label={`Show PCAPs for ${item.ip}`}
                          onClick={() => setSelectedIpPcaps(item)}
                          className="rounded-lg bg-violet-500/10 px-2.5 py-1 font-semibold text-violet-700 transition hover:bg-violet-500/20 focus:outline-none focus:ring-2 focus:ring-violet-500 focus:ring-offset-2"
                        >
                          {formatNumber(item.pcap_ids?.length)}
                        </button>
                      </td>
                      <td className="px-4 py-3 text-sm text-slate-600">
                        <span className="inline-flex items-center gap-2">
                          {countryFlag ? (
                            <span
                              className={`${countryFlag} shrink-0 rounded-sm`}
                              aria-label={`${country} flag`}
                              title={country}
                            />
                          ) : (
                            <MapPin
                              size={14}
                              className="shrink-0 text-slate-400"
                            />
                          )}
                          <span className="truncate">{country}</span>
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          href={archiveLink(item.ip)}
                          onClick={() => setSelectedTime(null)}
                          className="inline-flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-2.5 py-1.5 text-xs font-semibold text-blue-700 transition hover:border-blue-400 hover:bg-blue-100"
                        >
                          More info
                          <ArrowUpRight size={12} />
                        </Link>
                      </td>
                      </tr>
                    );
                  })}
                  {!selectedTimeIps.length && (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-10 text-center text-sm text-slate-500"
                      >
                        No IPs were recorded at this timestamp.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
      {selectedIpDomains && (
        <div
          className="fixed inset-0 z-[1000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
          onClick={() => setSelectedIpDomains(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="connected-domains-title"
            className="w-full max-w-2xl rounded-2xl border border-blue-100 bg-white p-5 shadow-2xl sm:p-6"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="mb-5 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h2
                  id="connected-domains-title"
                  className="text-lg font-bold text-slate-900"
                >
                  Domains connected to this IP
                </h2>
                <p className="mt-1 truncate font-mono text-sm text-slate-500">
                  {selectedIpDomains.ip}
                </p>
              </div>
              <button
                type="button"
                aria-label="Close domains"
                onClick={() => setSelectedIpDomains(null)}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
              >
                <X size={18} />
              </button>
            </header>
            {selectedIpDomains.domains?.length ? (
              <div className="grid max-h-[60vh] grid-cols-1 gap-3 overflow-y-auto p-0.5 sm:grid-cols-2">
                {selectedIpDomains.domains.map((host) => (
                  <Link
                    key={host}
                    href={`/sinkhole/dnssinkhole/${encodeURIComponent(host)}`}
                    onClick={() => setSelectedIpDomains(null)}
                    className="group flex min-h-16 items-center justify-between gap-3 rounded-xl border border-blue-100 bg-white px-4 py-3 text-sm font-semibold text-slate-800 shadow-sm transition hover:border-blue-300 hover:bg-blue-50 hover:text-blue-800"
                  >
                    <span className="min-w-0 break-all">{host}</span>
                    <ArrowUpRight
                      size={16}
                      className="shrink-0 text-blue-500 transition group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                    />
                  </Link>
                ))}
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-blue-200 bg-blue-50/50 px-4 py-8 text-center text-sm text-slate-500">
                No domain names are available for this IP.
              </p>
            )}
          </section>
        </div>
      )}
      {selectedIpPcaps && (
        <div
          className="fixed inset-0 z-[1000] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[2px]"
          onClick={() => setSelectedIpPcaps(null)}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="connected-pcaps-title"
            className="w-full max-w-2xl rounded-2xl border border-blue-100 bg-white p-5 shadow-2xl sm:p-6"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="mb-5 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h2
                  id="connected-pcaps-title"
                  className="text-lg font-bold text-slate-900"
                >
                  PCAPs connected to this IP
                </h2>
                <p className="mt-1 truncate font-mono text-sm text-slate-500">
                  {selectedIpPcaps.ip}
                </p>
              </div>
              <button
                type="button"
                aria-label="Close PCAPs"
                onClick={() => setSelectedIpPcaps(null)}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-slate-500 transition hover:border-blue-200 hover:bg-blue-50 hover:text-blue-700"
              >
                <X size={18} />
              </button>
            </header>
            {selectedIpPcaps.pcap_ids?.length ? (
              <div className="grid max-h-[60vh] grid-cols-1 gap-3 overflow-y-auto p-0.5 sm:grid-cols-2">
                {selectedIpPcaps.pcap_ids.map((pcapId) => (
                  <Link
                    key={pcapId}
                    href={`/pcaps/${DNS_SINKHOLE_ID}?pcap=${encodeURIComponent(pcapId)}&tab=${encodeURIComponent("Pcap Summary")}`}
                    onClick={() => setSelectedIpPcaps(null)}
                    className="group flex min-h-16 items-center gap-3 rounded-xl border border-blue-100 bg-white px-4 py-3 text-sm font-semibold text-slate-800 shadow-sm transition hover:border-blue-300 hover:bg-blue-50 hover:text-blue-800"
                  >
                    <FileText size={17} className="shrink-0 text-violet-600" />
                    <span className="min-w-0 break-all">{pcapId}</span>
                    <ArrowUpRight
                      size={16}
                      className="ml-auto shrink-0 text-blue-500 transition group-hover:translate-x-0.5 group-hover:-translate-y-0.5"
                    />
                  </Link>
                ))}
              </div>
            ) : (
              <p className="rounded-xl border border-dashed border-blue-200 bg-blue-50/50 px-4 py-8 text-center text-sm text-slate-500">
                No PCAPs are available for this IP.
              </p>
            )}
          </section>
        </div>
      )}
    </main>
  );
}
