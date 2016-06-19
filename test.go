package main
import "fmt"

type X struct {
}

func (x *X)tt() {
    fmt.Println("OK")
}

func main() {
 //    c := 1
 //    buf := make([]int, 0, 10)
 //    fmt.Println(buf)
 //    fmt.Println(cap(buf), len(buf))
 //    buf2 := append(buf, 1)
 //    fmt.Println(buf)
 //    fmt.Println(buf2)
    x := X{}
    x.tt()
    y := x.tt
    y()
}
