import { getAuth } from "@/auth";
import { notFound, redirect } from "next/navigation";
import PcapErrorView from "@/app/pcaps/[setId]/PcapErrorView";
import {
  dnssinkhole,
  getDnsSinkholeDomainDetails,
} from "../dnsApiService";
import DomainDetailClient from "./DomainDetailClient";

export default async function DnsSinkholeDomainPage({ params }) {
  const session = await getAuth();
  if (!session) redirect("/");
  if (!session.user?.roles?.includes("admin")) redirect("/reports");
  if (!session.accessToken) {
    console.log("access token is missing while loading the DNS sinkhole page");
    return <PcapErrorView />;
  }

  const { domain } = await params;
  const dnsData = await dnssinkhole(session.accessToken);
  const selectedDomain = dnsData.find((item) => item.host === domain);

  if (!selectedDomain) notFound();

  const domainDetails = await getDnsSinkholeDomainDetails(
    session.accessToken,
    domain,
  );

  return (
    <DomainDetailClient
      selectedDomain={selectedDomain}
      domainDetails={domainDetails}
    />
  );
}
