export const BASE_URL =
  typeof window === "undefined" ? process.env.BACKEND_URL : "/api/proxy";

const DNS_SINKHOLE_ID = 2;

const fetchWithTimeout = async (url, options = {}) => {
  const { timeout = 30000, ...fetchOptions } = options;
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, {
      ...fetchOptions,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
};

export async function dnssinkhole(accessToken) {
  try {
    const res = await fetchWithTimeout(
      `${BASE_URL}/pcaps/${DNS_SINKHOLE_ID}/dns-sinkhole`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );

    if (!res.ok) throw new Error(`Failed to fetch dnsrequest:${res.status}`);
    const json = await res.json();
    return json.data;
  } catch (error) {
    console.log("error while fetching data from dns-sinkhole", error);
    throw error;
  }
}

export async function getDnsSinkholeDomainDetails(accessToken, domainName) {
  const res = await fetchWithTimeout(
    `${BASE_URL}/pcaps/${DNS_SINKHOLE_ID}/dns-sinkhole/domains/${encodeURIComponent(domainName)}/details`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch DNS sinkhole domain details: ${res.status}`);
  }
  const json = await res.json();
  return json.data;
}

export async function dnsSinkoleSummary(accessToken) {
  try {
    const res = await fetchWithTimeout(
      `${BASE_URL}/pcaps/${DNS_SINKHOLE_ID}/dns-sinkhole/summary`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
    if (!res.ok)
      throw new Error(`Failed to fetch dnsinkole summary data : ${res.status}`);
    const json = await res.json();
    return json.data;
  } catch (error) {
    console.log("error while fetching data from dns-sinkhole summary", error);
  }
}
export async function getISPdnsSinkholeDomain(domainName) {
  try {
    const res = await fetchWithTimeout(
      `${BASE_URL}/pcaps/set/${DNS_SINKHOLE_ID}/domains/${encodeURIComponent(domainName)}/isps`,
    );

    if (!res.ok) {
      throw new Error(`Failed to fetch ISP data: ${res.status}`);
    }

    const json = await res.json();

    return json.data;
  } catch (error) {
    console.log("error while fetching data of ISP from dns-sinkhole", error);
    throw error;
  }
}
