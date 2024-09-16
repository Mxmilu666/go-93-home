package Helper

import (
    "bytes"
)

type BMCLAPIObject struct {
    Path         string
    Hash         string
    Size         int64
    LastModified int64
}

type AvroEncoder struct {
    ByteStream bytes.Buffer
}

func NewAvroEncoder() *AvroEncoder {
    return &AvroEncoder{
        ByteStream: bytes.Buffer{},
    }
}

func longToByte(value int64) []byte {
    var o bytes.Buffer
    data := uint64((value << 1) ^ (value >> 63)) // ZigZag 编码
    for (data &^ 0x7F) != 0 {
        o.WriteByte(byte((data & 0x7F) | 0x80))
        data >>= 7
    }
    o.WriteByte(byte(data))
    return o.Bytes()
}

func (ae *AvroEncoder) SetElements(count int64) {
    ae.SetLong(count)
}

func (ae *AvroEncoder) SetLong(value int64) {
    ae.ByteStream.Write(longToByte(value))
}

func (ae *AvroEncoder) SetString(value string) {
    bytesValue := []byte(value)
    ae.ByteStream.Write(longToByte(int64(len(bytesValue))))
    ae.ByteStream.Write(bytesValue)
}

func (ae *AvroEncoder) SetBytes(value []byte) {
    ae.ByteStream.Write(longToByte(int64(len(value))))
    ae.ByteStream.Write(value)
}

func (ae *AvroEncoder) SetEnd() {
    ae.ByteStream.WriteByte(0x00)
}

func ComputeAvroBytes(elements []BMCLAPIObject) ([]byte, error) {
    encoder := NewAvroEncoder()
    encoder.SetElements(int64(len(elements)))
    for _, file := range elements {
        encoder.SetString(file.Path)
        encoder.SetString(file.Hash)
        encoder.SetLong(file.Size)
        encoder.SetLong(file.LastModified)
    }
    encoder.SetEnd()

    // 获取编码后的字节数据
    bytesData := encoder.ByteStream.Bytes()

    return bytesData, nil
}