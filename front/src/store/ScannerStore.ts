/* eslint-disable @typescript-eslint/no-explicit-any */
import { makeAutoObservable, runInAction } from "mobx";
import axios from "axios";
import { Host, SshAttempt } from "../types/Host";

const mockData = false
const url = `http://localhost:8081/${mockData ? 'apifake' : 'api'}`


export class ScannerStore {

  rangeIp = "";
  progress = "";
  hosts: Host[] = [];
  loading = false;

  selectedHost: Host | null = null;

  sshBruteResults: SshAttempt | null = null;

  constructor() {
    makeAutoObservable(this);
  }

  setRangeIp(ip: string) {
    this.rangeIp = ip;
  }

  setSelectedHost(host: Host | null) {
    this.selectedHost = host;
  }

  async scanNetwork() {
    this.loading = true;
    this.hosts = [];
    this.setSelectedHost(null);
    try {
      await axios.get(`${url}/scanallhost`, {
        params: { range_ip: this.rangeIp },
      });
      this.pollProgress();
    } catch (error) {
      console.error("Ошибка при сканировании сети", error);
      runInAction(() => {
        this.loading = false;
      });
    }
  }

  async pollProgress() {
    const interval = setInterval(async () => {
      try {
        const res = await axios.get(`${url}/get_proc`);
        runInAction(() => {
          this.progress = res.data.percent;
        });

        if (res.data.percent === "done") {
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
    
    console.log('Updated ports:', res); // Для отладки
    runInAction(() => {
      const portData = res.data.port_res.find((item: any) => item.id === id);
      const ports = portData?.ports || [];
      
      // Обновляем hosts
      this.hosts = this.hosts.map(host => 
        host.id === id ? { ...host, openPorts: ports } : host
      );
      
      // Обновляем selectedHost
      if (this.selectedHost?.id === id) {
        this.setSelectedHost({ 
          ...this.selectedHost, 
          openPorts: ports 
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
}

export const scannerStore = new ScannerStore();