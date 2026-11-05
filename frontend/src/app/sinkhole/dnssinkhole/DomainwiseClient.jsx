"use client";
import { useState, useMemo, useLayoutEffect, useRef } from "react";
import Link from "next/link";
import {
  Search,
  ChevronRight,
  Activity,
  ArrowUp,
  ArrowDown,
  Filter,
  Hash,
} from "lucide-react";
import { FileText, Network, LayoutDashboard } from "lucide-react";

const SORT_OPTIONS = [
  { id: "random", label: "Random" },
  { id: "name", label: "Alphabetical" },
  { id: "requests", label: "Requests" },
  { id: "ips", label: "Connected IPs" },
  { id: "pcaps", label: "PCAPs" },
];

const getShuffleScore = (host, seed) => {
  let score = seed;
  for (let index = 0; index < host.length; index += 1) {
    score = (Math.imul(score, 31) + host.charCodeAt(index)) | 0;
  }
  return score >>> 0;
};

export default function DomainwiseClient({ dnsData }) {
  const total_domains = dnsData.length;
  const [searchDomain, setSearchDomain] = useState("");

  const [sortBy, setSortBy] = useState("random");
  const [sortDirection, setSortDirection] = useState("asc");
  const [randomSeed, setRandomSeed] = useState(0);

  const cardRefs = useRef(new globalThis.Map());
  const previousPositions = useRef(new globalThis.Map());

  const filterDomains = useMemo(
    () =>
      dnsData.filter((item) =>
        item.host.toLowerCase().includes(searchDomain.toLowerCase()),
      ),
    [dnsData, searchDomain],
  );
  const randomOrder = useMemo(
    () =>
      [...filterDomains].sort(
        (a, b) =>
          getShuffleScore(a.host, randomSeed) -
          getShuffleScore(b.host, randomSeed),
      ),
    [filterDomains, randomSeed],
  );

  const sortedDomains =
    sortBy === "random" && randomOrder.length > 0
      ? randomOrder.filter((item) =>
          item.host.toLowerCase().includes(searchDomain.toLowerCase()),
        )
      : [...filterDomains].sort((a, b) => {
          if (sortBy == "random") {
            return 0;
          }
          let valueA;
          let valueB;

          switch (sortBy) {
            case "name":
              valueA = a.host.toLowerCase();
              valueB = b.host.toLowerCase();
              break;

            case "requests":
              valueA = Number(a.request_count) || 0;
              valueB = Number(b.request_count) || 0;
              break;

            case "ips":
              valueA = Number(a.connected_ip_count) || 0;
              valueB = Number(b.connected_ip_count) || 0;
              break;

            case "pcaps":
              valueA = Array.isArray(a.pcap_ids) ? a.pcap_ids.length : 0;
              valueB = Array.isArray(b.pcap_ids) ? b.pcap_ids.length : 0;
              break;

            default:
              return 0;
          }
          if (sortDirection === "asc") {
            return typeof valueA === "string"
              ? valueA.localeCompare(valueB)
              : valueA - valueB;
          }
          return typeof valueA === "string"
            ? valueB.localeCompare(valueA)
            : valueB - valueA;
        });

  useLayoutEffect(() => {
    if (previousPositions.current.size === 0) return;

    cardRefs.current.forEach((element, host) => {
      const previous = previousPositions.current.get(host);

      if (!previous || !element) return;

      const current = element.getBoundingClientRect();

      const deltaX = previous.left - current.left;
      const deltaY = previous.top - current.top;

      if (deltaX === 0 && deltaY === 0) return;

      element.animate(
        [
          {
            transform: `translate(${deltaX}px, ${deltaY}px)`,
          },
          {
            transform: "translate(0, 0)",
          },
        ],
        {
          duration: 700,
          easing: "cubic-bezier(0.22, 1, 0.36, 1)",
        },
      );
    });

    previousPositions.current.clear();
  }, [sortedDomains]);
  const captureCardPositions = () => {
    const positions = new globalThis.Map();

    cardRefs.current.forEach((element, host) => {
      if (element) {
        positions.set(host, element.getBoundingClientRect());
      }
    });

    previousPositions.current = positions;
  };

  return (
    <div className="flex h-[calc(100vh-56px)] flex-col overflow-hidden">
          <div className="flex items-center justify-between gap-4 px-6 pt-2 pb-4">
            <div className="flex items-center gap-4">
              <h1 className="flex items-center gap-3 text-[22px] font-bold tracking-tight text-foreground">
                DNS Sinkhole
                <span className="inline-flex items-center gap-1.5 rounded-md border border-orange-200 bg-orange-50 px-3 py-1.5 text-xs font-semibold text-orange-700 shadow-sm">
                  <span className="font-bold tabular-nums">
                    {total_domains}
                  </span>
                  <span>Domains</span>
                </span>
              </h1>
              <Link
                href="/sinkhole/dnssinkhole/overview"
                className="group inline-flex items-center gap-2 rounded-md border border-blue-200 bg-blue-50 px-3.5 py-2 text-sm font-semibold text-blue-700 shadow-sm transition-colors hover:border-blue-300 hover:bg-blue-100 focus-visible:outline-none focus-visible:ring-4 focus-visible:ring-blue-500/20"
              >
                <LayoutDashboard
                  size={16}
                  className="text-blue-600 transition-transform group-hover:scale-110"
                />
                Overview
              </Link>
            </div>

            <div className="group relative w-full max-w-md">
              <Search
                size={15}
                className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 transition-colors group-focus-within:text-blue-500"
              />
              <input
                type="text"
                placeholder="Search domain..."
                value={searchDomain}
                onChange={(e) => setSearchDomain(e.target.value)}
                className="w-full rounded-xl border border-theme bg-card py-2.5 pl-10 pr-3 text-[13px] font-medium text-foreground shadow-sm transition-all placeholder:text-slate-500 focus:border-blue-500 focus:outline-none focus:ring-4 focus:ring-blue-500/10"
              />
            </div>
          </div>
          <div className="mx-6 mb-2 flex px-3 py-2 items-center gap-2 border border-theme bg-card rounded-xl shadow-sm">
            <Filter
              size={18}
              className="text-muted-foreground mx-2 text-slate-500"
            />
            {SORT_OPTIONS.map((option) => (
              <button
                key={option.id}
                onClick={() => {
                  captureCardPositions();
                  if (option.id === "random") {
                    setRandomSeed((seed) => seed + 1);
                    setSortBy("random");
                    return;
                  }
                  if (sortBy === option.id) {
                    setSortDirection(sortDirection === "asc" ? "desc" : "asc");
                  } else {
                    setSortBy(option.id);
                    setSortDirection("asc");
                  }
                }}
                className={`border flex items-center px-4 py-2 text-sm rounded-md font-medium text-foreground border-theme bg-card transition-all duration-200
                ${
                  sortBy === option.id
                    ? "!border-blue-500 !bg-blue-500 !text-white shadow-sm"
                    : "border-theme bg-card text-foreground hover:border-blue-500 hover:text-blue-500"
                }`}
              >
                <span>{option.label} </span>
                {sortBy === option.id &&
                  (sortDirection === "asc" ? (
                    <ArrowUp size={14} />
                  ) : (
                    <ArrowDown size={14} />
                  ))}
              </button>
            ))}
          </div>
          {sortedDomains.length > 0 ? (
            <div className="mx-6 mb-2 flex-1 min-h-0 overflow-y-auto rounded-2xl border border-theme bg-card/40 p-5 shadow-sm">
              <div className="grid grid-cols-1 gap-4 pb-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
                {sortedDomains.map((item) => (
                  <Link
                    href={`/sinkhole/dnssinkhole/${encodeURIComponent(item.host)}`}
                    key={item.host}
                    ref={(el) => {
                      if (el) {
                        cardRefs.current.set(item.host, el);
                      } else {
                        cardRefs.current.delete(item.host);
                      }
                    }}
                    className="group relative flex min-h-[180px] cursor-pointer flex-col items-center gap-3 overflow-hidden rounded-xl border border-blue-300 p-4 shadow-md shadow-blue-200 transition-all duration-200 hover:-translate-y-0.5 hover:border-blue-600 hover:shadow-lg hover:shadow-blue-200"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <span
                        className="min-w-0 truncate text-[16px] font-semibold tracking-tight text-foreground"
                        title={item.host}
                      >
                        {item.host}
                      </span>
                    </div>

                    <div className="mt-2 w-full px-4">
                      <div className="grid w-full grid-cols-2 gap-x-2 gap-y-6 text-[16px] text-muted-foreground">
                        {/* Requests */}
                        <div className="flex items-center gap-3">
                          <Activity
                            size={16}
                            className="shrink-0 text-emerald-500"
                          />
                          <div className="flex flex-col">
                            <span className="font-bold text-foreground">
                              {Number(item.request_count).toLocaleString(
                                "en-IN",
                              )}
                            </span>
                            <span className="text-[14px] text-muted-foreground">
                              Requests
                            </span>
                          </div>
                        </div>

                        {/* Connected IPs */}
                        <div className="flex items-center gap-3">
                          <Hash
                            size={16}
                            className="shrink-0 text-violet-500"
                          />
                          <div className="flex flex-col">
                            <span className="font-bold text-foreground">
                              {Number(item.connected_ip_count).toLocaleString(
                                "en-IN",
                              )}
                            </span>
                            <span className="text-[14px] text-muted-foreground">
                              IPs
                            </span>
                          </div>
                        </div>

                        {/* PCAPs */}
                        <div className="flex items-center gap-3">
                          <FileText
                            size={16}
                            className="shrink-0 text-orange-500"
                          />
                          <div className="flex flex-col">
                            <span className="font-bold text-foreground">
                              {Number(
                                item.pcap_ids?.length ?? 0,
                              ).toLocaleString("en-IN")}
                            </span>
                            <span className="text-[14px] text-muted-foreground">
                              PCAPs
                            </span>
                          </div>
                        </div>

                        {/* Connections */}
                        <div className="flex items-center gap-3">
                          <Network
                            size={16}
                            className="shrink-0 text-blue-500"
                          />
                          <div className="flex flex-col">
                            <span className="font-bold text-foreground">
                              {Number(
                                item.total_connections ?? 0,
                              ).toLocaleString("en-IN")}
                            </span>
                            <span className="text-[14px] text-muted-foreground">
                              Connections
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <ChevronRight
                      size={14}
                      className="ml-auto shrink-0 -translate-x-1 text-slate-400 opacity-0 transition-all group-hover:translate-x-0 group-hover:opacity-100"
                    />
                  </Link>
                ))}
              </div>
            </div>
          ) : (
            <div className="mx-6 flex flex-col items-center gap-2 rounded-xl border border-dashed border-theme py-16 text-muted-foreground">
              <Search size={22} className="opacity-50" />
              <span className="text-sm">No domains found</span>
            </div>
          )}
    </div>
  );
}
