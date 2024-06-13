package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/ast/astutil"
	"golang.org/x/tools/go/packages"
	"log"
	"path"
	"path/filepath"
	"strings"
)

func compile(src string) []byte {
	log.SetFlags(log.Lshortfile)
	c := &compiler{}
	sts := c.getStructs(src)
	pkgName := c.file.Name.Name
	fileId := path.Join(c.pkg.ID, path.Base(src))

	f := genFileHeader(pkgName, fileId)
	for _, st := range sts {
		enc, dec := c.shouldGen(st)
		if enc {
			f.Decls = append(f.Decls, c.genEncode(st))
		}
		if dec {
			f.Decls = append(f.Decls, c.genDecode(st))
		}
	}
	return printGo(f)
}

type compiler struct {
	pkg  *packages.Package
	file *ast.File
}

// getStructs post-cond: return struct objects.
func (c *compiler) getStructs(src string) []types.Object {
	abs, err := filepath.Abs(src)
	if err != nil {
		log.Panic(err)
	}
	dir := path.Dir(src)

	mode := packages.NeedName | packages.NeedFiles
	mode |= packages.NeedImports | packages.NeedDeps
	mode |= packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	cfg := &packages.Config{
		Mode: mode,
		Dir:  dir,
	}
	pkgs, err := packages.Load(cfg, "")
	if err != nil {
		log.Panic(err)
	}
	if len(pkgs) != 1 {
		log.Panic("pkg len not 1")
	}
	pkg := pkgs[0]
	c.pkg = pkg
	info := pkg.TypesInfo

	var file *ast.File
	for _, f := range pkg.Syntax {
		tokF := pkg.Fset.File(f.FileStart)
		if abs == tokF.Name() {
			file = f
		}
	}
	if file == nil {
		log.Panic("found no files matching src. does src end in .go?")
	}
	c.file = file

	var sts []types.Object
	for _, d := range file.Decls {
		d2, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		if d2.Tok != token.TYPE {
			continue
		}
		s, ok := d2.Specs[0].(*ast.TypeSpec)
		if !ok {
			continue
		}
		_, ok = s.Type.(*ast.StructType)
		if !ok {
			continue
		}
		o, ok := info.Defs[s.Name]
		if !ok {
			log.Panic(s.Name, " is not in defs map")
		}
		_ = o.Type().Underlying().(*types.Struct)
		sts = append(sts, o)
	}
	return sts
}

func genFileHeader(pkgName, fileId string) *ast.File {
	importDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/mit-pdos/pav/marshalutil\"",
				},
			},
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/tchajed/marshal\"",
				},
			},
		},
	}
	// Hacky: pkg comment fix. Pkg starts after pkg comment.
	commPos := token.Pos(1)
	comm1 := &ast.Comment{
		Slash: commPos,
		Text:  fmt.Sprintf("// Auto-generated from spec \"%s\"", fileId),
	}
	comm2 := &ast.Comment{
		Slash: commPos,
		Text:  "// using compiler \"github.com/mit-pdos/pav/rpc\".",
	}
	file := &ast.File{
		Doc:     &ast.CommentGroup{List: []*ast.Comment{comm1, comm2}},
		Package: commPos + 1,
		Name:    &ast.Ident{Name: pkgName},
		Decls: []ast.Decl{
			importDecl,
		},
	}
	return file
}

// shouldGen checks whether a struct has special comments to not gen some funcs.
func (c *compiler) shouldGen(o types.Object) (encode bool, decode bool) {
	encode, decode = true, true
	p, _ := astutil.PathEnclosingInterval(c.file, o.Pos(), o.Pos())
	// First two are Ident and TypeSpec.
	d := p[2].(*ast.GenDecl)
	if d.Doc == nil {
		return
	}
	for _, comm := range d.Doc.List {
		if comm.Text == "// rpc: no encode needed." {
			encode = false
		}
		if comm.Text == "// rpc: no decode needed." {
			decode = false
		}
	}
	return
}

func (c *compiler) genEncode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Results: &ast.FieldList{
			List: []*ast.Field{{
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
	}
	callMake := &ast.CallExpr{
		Fun: &ast.Ident{Name: "make"},
		Args: []ast.Expr{
			&ast.ArrayType{
				Elt: &ast.Ident{Name: "byte"},
			},
			&ast.BasicLit{Kind: token.INT, Value: "0"},
		},
	}
	makeByteSl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{callMake},
				},
			},
		},
	}
	body := []ast.Stmt{makeByteSl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldWrite(field))
	}
	retStmt := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
		},
	}
	body = append(body, retStmt)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "encode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func genRcvr(name string) *ast.FieldList {
	return &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{Name: "o"}},
			Type:  &ast.StarExpr{X: &ast.Ident{Name: name}},
		}},
	}
}

func (c *compiler) genFieldWrite(field *types.Var) ast.Stmt {
	var call *ast.CallExpr
	switch fTy := field.Type().(type) {
	case *types.Slice:
		call = &ast.CallExpr{
			Fun:  c.genSliceWrite(field.Pos(), fTy, 1),
			Args: genStdFieldWriteArgs(field.Name()),
		}
	case *types.Basic:
		switch fTy.Kind() {
		case types.Uint64:
			call = c.genIntWrite(field)
		case types.Bool:
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "WriteBool"},
				},
				Args: genStdFieldWriteArgs(field.Name()),
			}
		default:
			log.Panic("unsupported type: ", fTy.Name())
		}
	default:
		log.Panic("unsupported type: ", fTy)
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "b"}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{call},
	}
}

func (c *compiler) genSliceWrite(pos token.Pos, ty1 *types.Slice, depth int) *ast.SelectorExpr {
	if depth > 3 {
		log.Panic("unsupported slice nesting beyond depth 3")
	}
	switch ty2 := ty1.Elem().(type) {
	case *types.Slice:
		return c.genSliceWrite(pos, ty2, depth+1)
	case *types.Basic:
		if ty2.Kind() != types.Byte {
			log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
		}
		isFixed, _ := c.getFixedLen(pos)
		if isFixed {
			if depth == 1 {
				return &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshal"},
					Sel: &ast.Ident{Name: "WriteBytes"},
				}
			} else {
				log.Panicf("unsupported fixed len outside depth 1 slices")
			}
		}
		return &ast.SelectorExpr{
			X:   &ast.Ident{Name: "marshalutil"},
			Sel: &ast.Ident{Name: fmt.Sprintf("WriteSlice%vD", depth)},
		}
	default:
		log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
	}
	return nil
}

// getFixedLen uses field pos to check if has special fixed len comment.
func (c *compiler) getFixedLen(pos token.Pos) (isFixed bool, length string) {
	p, _ := astutil.PathEnclosingInterval(c.file, pos, pos)
	// First node is ident, then there's field.
	node := p[1].(*ast.Field)
	if node.Doc == nil {
		return false, ""
	}
	comm := node.Doc.List[0].Text
	comm = strings.TrimPrefix(comm, "// rpc: invariant: len ")
	comm = strings.TrimRight(comm, ".")
	return true, comm
}

func (c *compiler) genIntWrite(field *types.Var) *ast.CallExpr {
	fun := &ast.SelectorExpr{
		X:   &ast.Ident{Name: "marshal"},
		Sel: &ast.Ident{Name: "WriteInt"},
	}
	isCst, cst := c.getConst(field.Pos())
	if isCst {
		return &ast.CallExpr{
			Fun: fun,
			Args: []ast.Expr{
				&ast.Ident{Name: "b"},
				&ast.BasicLit{Kind: token.INT, Value: cst},
			},
		}
	} else {
		return &ast.CallExpr{
			Fun:  fun,
			Args: genStdFieldWriteArgs(field.Name()),
		}
	}
}

// getConst uses ast pos to check if field has special constant comment.
func (c *compiler) getConst(pos token.Pos) (isCst bool, cst string) {
	p, _ := astutil.PathEnclosingInterval(c.file, pos, pos)
	// First node is ident, then there's field.
	node := p[1].(*ast.Field)
	if node.Doc == nil {
		return false, ""
	}
	comm := node.Doc.List[0].Text
	comm = strings.TrimPrefix(comm, "// rpc: invariant: const ")
	comm = strings.TrimRight(comm, ".")
	return true, comm
}

func genStdFieldWriteArgs(name string) []ast.Expr {
	return []ast.Expr{
		&ast.Ident{Name: "b"},
		&ast.SelectorExpr{
			X:   &ast.Ident{Name: "o"},
			Sel: &ast.Ident{Name: name},
		},
	}
}

func (c *compiler) genDecode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Params: &ast.FieldList{
			List: []*ast.Field{{
				Names: []*ast.Ident{{Name: "b0"}},
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
		Results: &ast.FieldList{
			List: []*ast.Field{
				{Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				}},
				{Type: &ast.Ident{Name: "errorTy"}},
			},
		},
	}
	varDecl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{&ast.Ident{Name: "b0"}},
				},
			},
		},
	}
	ret := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "errNone"},
		},
	}
	body := []ast.Stmt{varDecl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, c.genFieldRead(field)...)
	}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, genFieldAssign(field))
	}
	body = append(body, ret)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "decode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func genFieldAssign(field *types.Var) ast.Stmt {
	name := field.Name()
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.SelectorExpr{
			X:   &ast.Ident{Name: "o"},
			Sel: &ast.Ident{Name: name},
		}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.Ident{Name: name}},
	}
}

func (c *compiler) genFieldRead(field *types.Var) []ast.Stmt {
	name := field.Name()
	var call *ast.CallExpr
	switch fTy := field.Type().(type) {
	case *types.Slice:
		call = c.genSliceRead(field.Pos(), fTy, 1)
	case *types.Basic:
		switch fTy.Kind() {
		case types.Uint64:
			call = c.genIntRead(field)
		case types.Bool:
			call = &ast.CallExpr{
				Fun: &ast.SelectorExpr{
					X:   &ast.Ident{Name: "marshalutil"},
					Sel: &ast.Ident{Name: "ReadBool"},
				},
				Args: []ast.Expr{&ast.Ident{Name: "b"}},
			}
		default:
			log.Panic("unsupported type: ", fTy.Name())
		}
	default:
		log.Panic("unsupported type: ", fTy)
	}
	assign := &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: name},
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "err"},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{call},
	}
	err := &ast.IfStmt{
		Cond: &ast.Ident{Name: "err"},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{
				Results: []ast.Expr{
					&ast.Ident{Name: "nil"},
					&ast.Ident{Name: "err"},
				},
			},
		}},
	}
	return []ast.Stmt{assign, err}
}

func (c *compiler) genSliceRead(pos token.Pos, ty1 *types.Slice, depth int) *ast.CallExpr {
	if depth > 3 {
		log.Panic("unsupported slice nesting beyond depth 3")
	}
	switch ty2 := ty1.Elem().(type) {
	case *types.Slice:
		return c.genSliceRead(pos, ty2, depth+1)
	case *types.Basic:
		if ty2.Kind() != types.Byte {
			log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
		}
		isFixed, length := c.getFixedLen(pos)
		if isFixed {
			if depth == 1 {
				return &ast.CallExpr{
					Fun: &ast.SelectorExpr{
						X:   &ast.Ident{Name: "marshalutil"},
						Sel: &ast.Ident{Name: "SafeReadBytes"},
					},
					Args: []ast.Expr{
						&ast.Ident{Name: "b"},
						&ast.BasicLit{Kind: token.INT, Value: length},
					},
				}
			} else {
				log.Panicf("unsupported fixed len outside depth 1 slices")
			}
		}
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: fmt.Sprintf("ReadSlice%vD", depth)},
			},
			Args: []ast.Expr{&ast.Ident{Name: "b"}},
		}
	default:
		log.Panicf("unsupported slice depth %v ty: %s", depth, ty2)
	}
	return nil
}

func (c *compiler) genIntRead(field *types.Var) *ast.CallExpr {
	isCst, cst := c.getConst(field.Pos())
	if isCst {
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: "ReadConstInt"},
			},
			Args: []ast.Expr{
				&ast.Ident{Name: "b"},
				&ast.BasicLit{Kind: token.INT, Value: cst},
			},
		}
	} else {
		return &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: "SafeReadInt"},
			},
			Args: []ast.Expr{&ast.Ident{Name: "b"}},
		}
	}
}

func printGo(n any) []byte {
	fset := token.NewFileSet()
	// Hacky: pkg comment fix. Range big enough to fit both specified pos's.
	fset.AddFile("out.go", 1, 1)
	buf := new(bytes.Buffer)
	err := format.Node(buf, fset, n)
	if err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}
