// Code generated by protoc-gen-goext. DO NOT EDIT.

package monitoring

type LabelValuesParameter_Container = isLabelValuesParameter_Container

func (m *LabelValuesParameter) SetContainer(v LabelValuesParameter_Container) {
	m.Container = v
}

func (m *LabelValuesParameter) SetFolderId(v string) {
	m.Container = &LabelValuesParameter_FolderId{
		FolderId: v,
	}
}

func (m *LabelValuesParameter) SetSelectors(v string) {
	m.Selectors = v
}

func (m *LabelValuesParameter) SetLabelKey(v string) {
	m.LabelKey = v
}

func (m *LabelValuesParameter) SetMultiselectable(v bool) {
	m.Multiselectable = v
}

func (m *LabelValuesParameter) SetDefaultValues(v []string) {
	m.DefaultValues = v
}

func (m *CustomParameter) SetValues(v []string) {
	m.Values = v
}

func (m *CustomParameter) SetMultiselectable(v bool) {
	m.Multiselectable = v
}

func (m *CustomParameter) SetDefaultValues(v []string) {
	m.DefaultValues = v
}

func (m *TextParameter) SetDefaultValue(v string) {
	m.DefaultValue = v
}

func (m *DoubleParameter) SetDefaultValue(v float64) {
	m.DefaultValue = v
}

func (m *DoubleParameter) SetUnitFormat(v UnitFormat) {
	m.UnitFormat = v
}

func (m *IntegerParameter) SetDefaultValue(v int64) {
	m.DefaultValue = v
}

func (m *IntegerParameter) SetUnitFormat(v UnitFormat) {
	m.UnitFormat = v
}

func (m *TextValuesParameter) SetDefaultValues(v []string) {
	m.DefaultValues = v
}

type Parameter_Data = isParameter_Data

func (m *Parameter) SetData(v Parameter_Data) {
	m.Data = v
}

func (m *Parameter) SetName(v string) {
	m.Name = v
}

func (m *Parameter) SetTitle(v string) {
	m.Title = v
}

func (m *Parameter) SetLabelValues(v *LabelValuesParameter) {
	m.Data = &Parameter_LabelValues{
		LabelValues: v,
	}
}

func (m *Parameter) SetCustom(v *CustomParameter) {
	m.Data = &Parameter_Custom{
		Custom: v,
	}
}

func (m *Parameter) SetText(v *TextParameter) {
	m.Data = &Parameter_Text{
		Text: v,
	}
}

func (m *Parameter) SetIntegerParameter(v *IntegerParameter) {
	m.Data = &Parameter_IntegerParameter{
		IntegerParameter: v,
	}
}

func (m *Parameter) SetDoubleParameter(v *DoubleParameter) {
	m.Data = &Parameter_DoubleParameter{
		DoubleParameter: v,
	}
}

func (m *Parameter) SetTextValues(v *TextValuesParameter) {
	m.Data = &Parameter_TextValues{
		TextValues: v,
	}
}

func (m *Parameter) SetHidden(v bool) {
	m.Hidden = v
}

func (m *Parameter) SetDescription(v string) {
	m.Description = v
}

func (m *Parametrization) SetParameters(v []*Parameter) {
	m.Parameters = v
}

func (m *Parametrization) SetSelectors(v string) {
	m.Selectors = v
}
