import { SearchOutlined } from "@ant-design/icons";
import { Input } from "antd";
import "../styles/list-toolbar.css";

export default function ListSearch({ value, onChange, placeholder }: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return <Input className="list-search" allowClear prefix={<SearchOutlined />} aria-label={placeholder} placeholder={placeholder} value={value} onChange={event => onChange(event.target.value)} />;
}
