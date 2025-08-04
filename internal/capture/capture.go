package capture

import (
	"github.com/arya2004/fynewire/internal/model"
)

func Interfaces() ([]string, error) {

	return []string{ "wlp2s0"}, nil

}

func Start(dev string) (<-chan model.Packet, error) {

	if err := open(dev); err != nil {
		return nil, err
	}

	out := make(chan model.Packet)
	go func() {
		defer func(){
			closeCap()
			close(out)
		}()

		for {
			s, d, ok := next()
			if !ok {
				continue
			}
			out <- model.Packet{Summary: s, Detail: d}
		}

	}()

	return out, nil

}


