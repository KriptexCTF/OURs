import { observer } from "mobx-react-lite";
import { scannerStore } from "../store/ScannerStore";
import { Card, Descriptions, Typography, Row, Col, Tag, Button, Space, Progress } from "antd";
import { ThunderboltOutlined } from "@ant-design/icons";

const { Text } = Typography;

export const NetworkCanvas = observer(() => {
  const host = scannerStore.selectedHost;
  if (!host) return null;

  const hasSshPort = host.openPorts?.some(port => port.service === "ssh");
  const hasFtpPort = host.openPorts?.some(port => port.service === "ftp");

  const handleSshBrute = () => {
    if (host.id) {
      scannerStore.sshBrute(host.id);
      scannerStore.pollSshProgress();
    }
  };

  const handleFtpBrute = () => {
    if (host.id) {
      scannerStore.ftpBrute(host.id);
      scannerStore.pollFtpProgress()
    }
  };

  return (
    <Card
      title={<><ThunderboltOutlined style={{ marginRight: 8 }} />Сетевая карта: {host.ip}</>}
      style={{ marginTop: 20 }}
      variant="borderless"
    >
      <Row gutter={16}>
        <Col span={12}>
          <Card title="Информация о хосте" variant="borderless">
            <Descriptions column={1}>
              <Descriptions.Item label="ID"><Text strong>{host.id}</Text></Descriptions.Item>
              <Descriptions.Item label="IP"><Text strong>{host.ip}</Text></Descriptions.Item>
              <Descriptions.Item label="MAC"><Text code>{host.mac}</Text></Descriptions.Item>
              <Descriptions.Item label="Производитель"><Text>{host.vendor}</Text></Descriptions.Item>
              <Descriptions.Item label="Имя хоста"><Text>{host.hostname || 'Неизвестно'}</Text></Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        <Col span={12}>
          <Card title="Открытые порты" variant="borderless">
            {host.openPorts?.length ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {host.openPorts.map(port => (
                  <Tag color="blue" key={port.port}>
                    {port.port} ({port.service})
                  </Tag>
                ))}
              </div>
            ) : (
              <Text type="secondary">Порты не сканированы</Text>
            )}
          </Card>

          {(hasSshPort || hasFtpPort) && (
            <Card title="Действия" style={{ marginTop: 16 }} variant="borderless">
              <Space direction="vertical" style={{ width: "100%" }}>
                {hasSshPort && (
                  <>
                    <Button onClick={handleSshBrute} disabled={scannerStore.loading} type="primary">
                      Запустить SSH Брут
                    </Button>
                    {scannerStore.sshProgress && scannerStore.sshProgress !== "done" && (
                      <Progress
                        percent={parseFloat(scannerStore.sshProgress)}
                        status="active"
                      />
                    )}
                  </>
                )}

                {hasFtpPort && (
                  <>
                    <Button onClick={handleFtpBrute} disabled={scannerStore.loading}>
                      Запустить FTP Брут
                    </Button>
                    {scannerStore.ftpProgress && scannerStore.ftpProgress !== "done" && (
                      <Progress
                        percent={parseFloat(scannerStore.ftpProgress)}
                        status="active"
                      />
                    )}
                  </>
                )}
              </Space>
            </Card>
          )}

          <Button onClick={()=>{
            scannerStore.fuzzingDir(host.id)

            // console.log(scannerStore.fuzzingDirResults.id)
            // console.log(JSON.stringify(scannerStore.fuzzingDirResults.id))
          }}>
            brute dir
          </Button>


          <Button onClick={()=>{
            // scannerStore.fuzzingDir(host.id)

            console.log(scannerStore.serachSploit(host.id))
          }}>
            search_exploits
          </Button>




          {scannerStore.sshBruteResults && (
            <Card title="SSH Доступ" style={{ marginTop: 16 }} variant="borderless">
              <Descriptions bordered>
                <Descriptions.Item label="Логин">
                  <Text strong>{scannerStore.sshBruteResults.username}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Пароль">
                  <Text strong type="danger">{scannerStore.sshBruteResults.password}</Text>
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}


          {scannerStore.ftpBruteResults && (
            <Card title="ftp Доступ" style={{ marginTop: 16 }} variant="borderless">
              <Descriptions bordered>
                <Descriptions.Item label="Логин">
                  <Text strong>{scannerStore.ftpBruteResults.username}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Пароль">
                  <Text strong type="danger">{scannerStore.ftpBruteResults.password}</Text>
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}




        </Col>
      </Row>
    </Card>
  );
});
