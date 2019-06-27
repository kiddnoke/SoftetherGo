package softetherApi

import (
	"encoding/binary"
	"reflect"
)

type protocol struct {
	PayLoad []byte
	Offset  int
}

func Protocol(payload []byte) (p *protocol) {
	return &protocol{
		PayLoad: payload,
		Offset:  0,
	}
}
func (p *protocol) GetRaw(size int) []byte {
	raw := p.PayLoad[p.Offset : p.Offset+size]
	p.Offset += size
	return raw
}
func (p *protocol) GetIntImpl(size int) uint64 {
	var i uint64
	raw := p.GetRaw(size)
	if size == 4 {
		i32 := binary.BigEndian.Uint32(raw)
		i = uint64(i32)
	} else {
		i64 := binary.BigEndian.Uint64(raw)
		i = i64
	}
	return i
}
func (p *protocol) GetInt() int {
	value := p.GetIntImpl(4)
	return int(value)
}

func (p *protocol) GetInt64() int64 {
	value := p.GetIntImpl(8)
	return int64(value)
}
func (p *protocol) GetString(offset int) string {
	return string(p.GetRaw(p.GetInt() - offset))
}
func (p *protocol) Deserialize() (output map[string]interface{}, err error) {
	output = make(map[string]interface{})
	count := p.GetInt()
	for i := 0; i < count; i++ {
		key := p.GetString(1)

		key_type := p.GetInt()
		key_value_count := p.GetInt()
		var getter func(index int) interface{}
		if key_type == 0 {
			getter = func(index int) interface{} {
				return p.GetInt()
			}
		} else if 1 == key_type {
			getter = func(index int) interface{} {
				ret := p.GetString(0)
				return []byte(ret)
			}
		} else if 2 <= key_type && key_type <= 3 {
			getter = func(index int) interface{} {
				return p.GetString(0)
			}
		} else if key_type == 4 {
			getter = func(index int) interface{} {
				return p.GetInt64()
			}
		}
		if key_value_count == 1 {
			output[key] = getter(0)
		} else {
			var key_value []interface{}
			for j := 0; j < key_value_count; j++ {
				key_value = append(key_value, getter(j))
			}
			output[key] = key_value
		}
	}
	return
}
func (p *protocol) SetRaw(raw []byte) {
	p.PayLoad = append(p.PayLoad, raw...)
}
func (p *protocol) SetIntImpl(value interface{}, size int) {
	if size == 4 {
		value_pack := make([]byte, 4)
		binary.BigEndian.PutUint32(value_pack, uint32(value.(int)))
		p.SetRaw(value_pack)
	} else {
		value_pack := make([]byte, 8)
		binary.BigEndian.PutUint64(value_pack, uint64(value.(int64)))
		p.SetRaw(value_pack)
	}
}
func (p *protocol) SetInt(value int) {
	p.SetIntImpl(value, 4)
}
func (p *protocol) SetInt64(value int64) {
	p.SetIntImpl(value, 8)
}
func (p *protocol) SetBoolean(value bool) {
	if value {
		p.SetInt(1)
	} else {
		p.SetInt(0)
	}
}
func (p *protocol) SetData(data []byte) {
	p.SetInt(len(data))
	p.SetRaw(data)
}

// ascii
func (p *protocol) SetString(str string, offset int) {
	value := []byte(str)
	p.SetInt(len(value) + offset)
	p.SetRaw(value[:])
}

// utf-8
func (p *protocol) SetUString(str string, offset int) {
	value := []byte(str)
	p.SetInt(len(value) + offset)
	p.SetRaw(value)
}

func (p *protocol) Serialize(input map[string][]interface{}) (payload []byte) {
	p.PayLoad = []byte{}
	p.SetInt(len(input))
	for k, value_tuple_list := range input {
		kind := reflect.TypeOf(value_tuple_list[0]).Kind()
		value := reflect.ValueOf(value_tuple_list[0])
		var value_type_int int
		switch kind {
		case reflect.Int:
			value_type_int = 0
		case reflect.String:
			value_type_int = 2
		case reflect.Int64:
			value_type_int = 4
		case reflect.Bool:
			value_type_int = 0
		case reflect.Slice:
			if value.Type() == reflect.TypeOf([]bool(nil)) {
				value_type_int = 0
			} else if value.Type() == reflect.TypeOf([]byte(nil)) {
				value_type_int = 1
			} else if value.Type() == reflect.TypeOf([]string{}) {
				value_type_int = 2
			} else if value.Type() == reflect.TypeOf([]int64{}) {
				value_type_int = 4
			}
		default:
			value_type_int = 1
		}
		p.SetString(k, 1)
		p.SetInt(value_type_int)
		p.SetInt(len(value_tuple_list))

		for index, item := range value_tuple_list {
			if value_type_int == 0 {
				p.SetInt(item.(int))
			} else if value_type_int == 1 {
				p.SetData(item.([]byte))
			} else if value_type_int == 2 {
				v := item.(string)
				p.SetString(v, index)
			} else if value_type_int == 3 {
				p.SetUString(item.(string), index)
			} else if value_type_int == 4 {
				p.SetInt64(item.(int64))
			}
		}
	}
	return p.PayLoad
}
