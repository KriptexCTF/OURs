export interface Host {
  id: string;
  ip: string;
  mac: string;
  hostname: string | null;
  vendor: string;
  openPorts?: PortScanResult[];
}

export interface PortScanResult {
  port: number;
  service: string;
}


export interface Attempt {
  username: string;
  password: string;
  success: boolean;
}

