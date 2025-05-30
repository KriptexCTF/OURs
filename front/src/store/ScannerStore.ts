/* eslint-disable @typescript-eslint/no-explicit-any */
import { makeAutoObservable, runInAction } from "mobx";
import axios from "axios";
import { Host, Attempt } from "../types/Host";

const mockData = false;
const url = `http://localhost:8081/${mockData ? 'apifake' : 'api'}`;

// add ftp -


export class ScannerStore {
  rangeIp = "192.168.0.1/24";

  scanProgress = "";
  sshProgress = "";
  ftpProgress = "";

  hosts: Host[] = [];
  loading = false;

  selectedHost: Host | null = null;
  sshBruteResults: Attempt | null = null;

  ftpBruteResults: Attempt | null = null;

  constructor() {
    makeAutoObservable(this);
  }

  setRangeIp(ip: string) {
    this.rangeIp = ip;
  }

  setSelectedHost(host: Host | null) {
    this.selectedHost = host;
  }

  async scanNetworkHost() {
    this.loading = true;
    this.hosts = [];
    this.setSelectedHost(null);
    this.scanProgress = "";

    try {
      await axios.get(`${url}/scanallhost`, {
        params: { range_ip: this.rangeIp },
      });

    } catch (error) {
      console.error("Ошибка при сканировании сети", error);
      runInAction(() => {
        this.loading = false;
      }) 
    }
  }

  async pollScanHostProgress() {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${url}/get_proc/`);
        const percentStr = res.data.percent;
        const numeric = percentStr === "done" ? "done" : percentStr.replace('%', '');

        runInAction(() => {
          this.scanProgress = numeric;
        });

        if (percentStr === "done") {
          clearInterval(interval);
          this.fetchResults();
        }
      } catch (error) {
        console.error("Ошибка при проверке прогресса", error);
        clearInterval(interval);
        runInAction(() => {
          this.loading = false;
        });
      }
    }, 1000);
  }

  async fetchResults() {
    try {
      const res = await axios.get(`${url}/scanallhost`, {
        params: { range_ip: this.rangeIp },
      });
      runInAction(() => {
        this.hosts = res.data.results;
        this.loading = false;
      });
    } catch (error) {
      console.error("Ошибка загрузки результатов", error);
      runInAction(() => {
        this.loading = false;
      });
    }
  }

  async scanPorts(id: string) {
    try {
      const res = await axios.post(`${url}/scanportsbyid/`, {
        targets: [id],
      });

      runInAction(() => {
        const portData = res.data.port_res.find((item: any) => item.id === id);
        const ports = portData?.ports || [];

        this.hosts = this.hosts.map(host =>
          host.id === id ? { ...host, openPorts: ports } : host
        );

        if (this.selectedHost?.id === id) {
          this.setSelectedHost({
            ...this.selectedHost,
            openPorts: ports,
          });
        }
      });
    } catch (error) {
      console.error("Ошибка при сканировании портов", error);
    }
  }

  async sshBrute(id: string) {
    try {
      const res = await axios.post(`${url}/ssh_brute/`, {
        targets: [id],
      });
      runInAction(() => {
        const sshData = res.data.ssh_res[0];
        const successAttempt = sshData?.users?.find((u: any) => u.password);
        
        this.sshBruteResults = successAttempt ? {
          username: successAttempt.username,
          password: successAttempt.password,
          success: true
        } : null;
      });
    } catch (error) {
      console.error("Ошибка при SSH брутфорсе", error);
    }
  }

  async pollSshProgress() {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${url}/ssh_proc/`);
        const percentStr = res.data.percent;
        const numeric = percentStr === "done" ? "done" : percentStr.replace('%', '');

        runInAction(() => {
          this.sshProgress = numeric;
        });

        if (percentStr === "done") {
          clearInterval(interval);
        }
      } catch (error) {
        console.error("Ошибка при проверке SSH прогресса", error);
        clearInterval(interval);
      }
    }, 1000);
  }

  async ftpBrute(id: string) {
    this.ftpBruteResults = null;

    try {
      const res = await axios.post(`${url}/ftp_brute/`, {
        targets: [id],
      });

      const result = res.data.ftp_res?.[0]?.users?.find((u: any) => u.password);

      runInAction(() => {
        if (result) {
          this.ftpBruteResults = {
            username: result.username,
            password: result.password,
            success: true,
          };
        } else {
          this.ftpBruteResults = null;
        }
      });

    } catch (error) {
      console.error("Ошибка при FTP брутфорсе", error);
    }
  }

  async pollFtpProgress() {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${url}/ftp_proc/`);
        const percentStr = res.data.percent;
        const numeric = percentStr === "done" ? "done" : percentStr.replace('%', '');

        runInAction(() => {
          this.ftpProgress = numeric;
        });

        if (percentStr === "done") {
          clearInterval(interval);
        }
      } catch (error) {
        console.error("Ошибка при проверке FTP прогресса", error);
        clearInterval(interval);
      }
    }, 1000);
  }
}

export const scannerStore = new ScannerStore();
