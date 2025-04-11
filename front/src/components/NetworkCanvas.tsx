import { observer } from "mobx-react-lite";
import { scannerStore } from "../store/ScannerStore";
import { Card, Descriptions, Typography, Row, Col, Tag, Button, Space } from "antd";
import { ThunderboltOutlined } from "@ant-design/icons";

const { Text } = Typography;

export const NetworkCanvas = observer(() => {
  if (!scannerStore.selectedHost) return null;

  const host = scannerStore.selectedHost;

  const hasSshPort = host.openPorts?.some(port => port.service === "ssh");

  const handleSshBrute = () => {
    if (host.id) {
      scannerStore.sshBrute(host.id);
    }
  };

  return (
    <Card 
      title={
        <span>
          <ThunderboltOutlined style={{ marginRight: 8 }} />
          Сетевая карта: {host.ip}
        </span>
      } 
      style={{ marginTop: 20 }}
      variant="borderless"
    >
      <Row gutter={16}>
        <Col span={12}>
          <Card title="Информация о хосте" variant="borderless">
            <Descriptions column={1}>
              <Descriptions.Item label="IP">
                <Text strong>{host.ip}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="MAC">
                <Text code>{host.mac}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Производитель">
                <Text>{host.vendor}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Имя хоста">
                <Text>{host.hostname || 'Неизвестно'}</Text>
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        <Col span={12}>
          <Card title="Открытые порты" variant="borderless">
            {host.openPorts?.length ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>

                {host.openPorts.map(port => (
                  <Tag 
                    color={'blue'} 
                    key={port.port}
                  >
                    {port.port} ({port.service})
                  </Tag>
                ))}

              </div>
            ) : (
              <Text type="secondary">Порты не сканированы</Text>
            )}
          </Card>

          {hasSshPort && (
            <Card title="Действия" style={{ marginTop: 16 }} variant="borderless">
              <Space>
                <Button 
                  type="primary" 
                  onClick={handleSshBrute}
                  disabled={scannerStore.loading}
                >
                  Запустить SSH Брут
                </Button>
              </Space>
            </Card>
          )}

          {scannerStore.sshBruteResults && (
            <Card title="SSH Доступ" style={{ marginTop: 16 }} variant="borderless">
              <Descriptions bordered>
                <Descriptions.Item label="Логин">
                  <Text strong>{scannerStore.sshBruteResults.username}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Пароль">
                  <Text strong type="danger">
                    {scannerStore.sshBruteResults.password}
                  </Text>
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}
        </Col>
      </Row>
    </Card>
  );
});