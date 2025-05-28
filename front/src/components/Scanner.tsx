/* eslint-disable @typescript-eslint/no-explicit-any */
import { observer } from "mobx-react-lite";
import { scannerStore } from "../store/ScannerStore";
import {
  Input,
  Button,
  Table,
  Space,
  Typography,
  Progress,
  Alert,
} from "antd";
import { NetworkCanvas } from "./NetworkCanvas";
import { useEffect } from "react";

// const { Title } = Typography;

export const Scanner = observer(() => {
  const columns = [
    {
      title: "IP",
      dataIndex: "ip",
      key: "ip",
      sorter: (a: any, b: any) => a.ip.localeCompare(b.ip),
    },
    {
      title: "MAC",
      dataIndex: "mac",
      key: "mac",
    },
    {
      title: "Host",
      dataIndex: "hostname",
      key: "hostname",
      sorter: (a: any, b: any) => a.hostname.localeCompare(b.hostname),
      render: (hostname: string | null) => hostname || "-",
    },
    {
      title: "Производитель",
      dataIndex: "vendor",
      key: "vendor",
      sorter: (a: any, b: any) => a.vendor.localeCompare(b.vendor),
    },
    {
      title: "Действия",
      key: "actions",
      render: (_: any, record: any) => (
        <Space>
          <Button
            onClick={() => {
              scannerStore.setSelectedHost(record);
              scannerStore.scanPorts(record.id);
            }}
            disabled={scannerStore.loading}
          >
            Скан портов
          </Button>
        </Space>
      ),
    },
  ];

  useEffect(()=>{
    console.log(scannerStore.scanProgress)
  })

  return (
    <div style={{ padding: 24 }}>
      <Typography.Title level={2}>Сканер сети</Typography.Title>

      <Space direction="vertical" style={{ width: "100%" }}>
        <Input
          placeholder="Введите range_ip (например 192.168.1.0/24)"
          value={scannerStore.rangeIp}
          onChange={(e) => scannerStore.setRangeIp(e.target.value)}
          style={{ width: "50vw" }}
          disabled={scannerStore.loading}
        />

        <Button
          type="primary"
          onClick={() => {
            scannerStore.scanNetworkHost()
            scannerStore.pollScanHostProgress()
          }}
          disabled={!scannerStore.rangeIp || scannerStore.loading}
          loading={scannerStore.loading}
        >
          Начать сканирование
        </Button>

        {scannerStore.scanProgress && scannerStore.scanProgress !== "done" && (
          <Progress
            percent={parseFloat(scannerStore.scanProgress)}
            status="active"
            style={{ width: 400 }}
          />
        )}

        {scannerStore.hosts.length > 0 && (
          <Alert
            message={`Найдено устройств: ${scannerStore.hosts.length}`}
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        <Table
          dataSource={scannerStore.hosts}
          columns={columns}
          rowKey="id"
          loading={scannerStore.loading}
          style={{ width: "100%" }}
          onRow={(record) => ({
            onClick: () => scannerStore.setSelectedHost(record),
            style: {
              cursor: "pointer",
              background:
                scannerStore.selectedHost?.id === record.id
                  ? "#f0f9ff"
                  : "inherit",
            },
          })}
        />

        {scannerStore.selectedHost && <NetworkCanvas />}
      </Space>
    </div>
  );
});
